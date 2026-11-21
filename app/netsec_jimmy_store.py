#!/usr/bin/env python3
"""Local, bounded, auditable Jimmy conversations, operator feedback, and push state.

Stored under /var/lib/server-status, not committed to the NetSec project.
No data in this module can execute commands or change CrowdSec decisions.
"""
import datetime as dt
from contextlib import contextmanager, closing
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3

DB = Path(os.environ.get('NETSEC_JIMMY_DB','/var/lib/server-status/jimmy-workspace.sqlite3'))
UTC=dt.timezone.utc
FEEDBACK_ACTIONS={'confirm','expected','own_ip','disagree','maintenance'}
MAX_MESSAGE=2000


def now():return dt.datetime.now(UTC)
def stamp():return now().isoformat()
def report_id(report):
    if not isinstance(report,dict) or not report.get('updated_at'):return None
    data=str(report['updated_at'])+'\n'+str(report.get('model',''))+'\n'+str(report.get('summary',''))
    return hashlib.sha256(data.encode()).hexdigest()[:24]


@contextmanager
def db():
    DB.parent.mkdir(mode=0o750,parents=True,exist_ok=True)
    conn=sqlite3.connect(str(DB),timeout=10)
    conn.execute('PRAGMA busy_timeout=10000')
    conn.execute('PRAGMA journal_mode=WAL')
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,body TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT, report_id TEXT NOT NULL,
      role TEXT NOT NULL,content TEXT NOT NULL,created_at TEXT NOT NULL,
      FOREIGN KEY(report_id) REFERENCES reports(id));
    CREATE INDEX IF NOT EXISTS msg_report ON messages(report_id,id);
    CREATE TABLE IF NOT EXISTS feedback(id INTEGER PRIMARY KEY AUTOINCREMENT, report_id TEXT NOT NULL,
      action TEXT NOT NULL,ip TEXT,note TEXT NOT NULL,author TEXT NOT NULL,
      created_at TEXT NOT NULL,expires_at TEXT,origin TEXT NOT NULL DEFAULT 'operator');
    CREATE INDEX IF NOT EXISTS feedback_expiry ON feedback(expires_at,created_at);
    CREATE TABLE IF NOT EXISTS subscriptions(id TEXT PRIMARY KEY,endpoint TEXT NOT NULL,
      p256dh TEXT NOT NULL,auth TEXT NOT NULL,created_at TEXT NOT NULL,last_success TEXT);
    CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,
      report_id TEXT NOT NULL,created_at TEXT NOT NULL,ack_at TEXT,notified_at TEXT,
      escalated_at TEXT,last_error TEXT);
    CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY,value TEXT NOT NULL);
    ''')
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def save_report(report):
    rid=report_id(report)
    if not rid:raise ValueError('No current assessment')
    limited={k:report.get(k) for k in ('updated_at','severity','summary','confidence','observations',
      'recommended_actions','verification_results','risk_assessment','model','source_generated_at',
      'operator_feedback_context')}
    with db() as c:
        c.execute('INSERT OR IGNORE INTO reports VALUES (?,?,?)',
                  (rid,stamp(),json.dumps(limited,ensure_ascii=False)[:20000]))
    return rid


def get_report(rid):
    if not isinstance(rid,str) or not re.fullmatch('[0-9a-f]{24}',rid):return None
    with db() as c:
        row=c.execute('SELECT body FROM reports WHERE id=?',(rid,)).fetchone()
    return json.loads(row[0]) if row else None


def messages(rid):
    with db() as c:
        rows=c.execute('SELECT role,content,created_at FROM messages WHERE report_id=? ORDER BY id DESC LIMIT 60',
                       (rid,)).fetchall()
    return [dict(zip(('role','content','at'),x)) for x in reversed(rows)]


def recent_messages(limit=60):
    """Global cross-assessment context, strictly ordered and bounded."""
    limit=max(1,min(int(limit),80))
    with db() as c:
        rows=c.execute('SELECT role,content,created_at FROM messages ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
    return [dict(zip(('role','content','at'),x)) for x in reversed(rows)]


def recent_reports(limit=5):
    """Recent saved assessments; newest first, for cautious historical comparison."""
    limit=max(1,min(int(limit),8))
    with db() as c:
        rows=c.execute('SELECT body FROM reports ORDER BY created_at DESC LIMIT ?', (limit,)).fetchall()
    return [json.loads(row[0]) for row in rows]


def add_exchange(rid,question,answer):
    if not isinstance(question,str) or not 1<=len(question.strip())<=MAX_MESSAGE:raise ValueError('Question length invalid')
    if not isinstance(answer,str) or not answer.strip():raise ValueError('Empty answer')
    with db() as c:
        for role,content in [('user',question.strip()),('assistant',answer[:10000])]:
            c.execute('INSERT INTO messages(report_id,role,content,created_at) VALUES (?,?,?,?)',
                      (rid,role,content,stamp()))
        # Bounded retention across all report threads.
        c.execute('DELETE FROM messages WHERE id NOT IN (SELECT id FROM messages ORDER BY id DESC LIMIT 1200)')


def add_feedback(rid,action,ip,note,author,ttl_hours=None):
    if action not in FEEDBACK_ACTIONS:raise ValueError('Invalid feedback action')
    if not isinstance(note,str) or len(note)>500:raise ValueError('Feedback note must be at most 500 characters')
    if not isinstance(author,str) or not 1<=len(author)<=64:raise ValueError('Invalid author')
    if ip:
        try:ip=str(ipaddress.ip_address(ip))
        except ValueError:raise ValueError('Invalid IP') from None
    if action=='own_ip' and not ip:raise ValueError('IP required for ownership confirmation')
    if action=='maintenance':
        if not isinstance(ttl_hours,int) or not 1<=ttl_hours<=168:
            raise ValueError('Maintenance requires 1-168 hours')
    elif ttl_hours is not None:
        if not isinstance(ttl_hours,int) or not 1<=ttl_hours<=2160:
            raise ValueError('TTL must be 1-2160 hours')
    # Non-permanent labels expire by default after seven days.
    expiry=None if action=='own_ip' else now()+dt.timedelta(hours=ttl_hours or 168)
    with db() as c:
        exists=c.execute('SELECT 1 FROM reports WHERE id=?',(rid,)).fetchone()
        if not exists:raise ValueError('Assessment not found')
        cur=c.execute('''INSERT INTO feedback(report_id,action,ip,note,author,created_at,expires_at)
                       VALUES (?,?,?,?,?,?,?)''',
                      (rid,action,ip,note.strip(),author,stamp(),expiry.isoformat() if expiry else None))
        return cur.lastrowid


def active_feedback(limit=30):
    # Scheduled AI uses ProtectSystem=strict and reads operator context only.
    # Never initialize or write the workspace database during AI assessments.
    if not DB.exists():return []
    try:
        with closing(sqlite3.connect('file:'+str(DB)+'?mode=ro',uri=True,timeout=5)) as c:
            rows=c.execute('''SELECT id,report_id,action,ip,note,author,created_at,expires_at,origin
                FROM feedback WHERE expires_at IS NULL OR expires_at > ? ORDER BY id DESC LIMIT ?''',
                (stamp(),min(100,max(1,limit)))).fetchall()
    except (sqlite3.Error,OSError):return []
    keys=['id','report_id','action','ip','note','author','created_at','expires_at','origin']
    return [dict(zip(keys,x)) for x in rows]


def get_kv(key,default=None):
    with db() as c:
        row=c.execute('SELECT value FROM kv WHERE key=?',(key,)).fetchone()
    return row[0] if row else default


def put_kv(key,value):
    with db() as c:c.execute('INSERT OR REPLACE INTO kv VALUES (?,?)',(key,str(value)))


def subscription_id(endpoint):return hashlib.sha256(endpoint.encode()).hexdigest()[:32]

def add_subscription(item):
    if not isinstance(item,dict):raise ValueError('Invalid subscription')
    endpoint=item.get('endpoint');keys=item.get('keys') or {}
    if not isinstance(endpoint,str) or len(endpoint)>1600 or not endpoint.startswith('https://') or '@' in endpoint:
        raise ValueError('Invalid push endpoint')
    from urllib.parse import urlsplit
    u=urlsplit(endpoint)
    if not u.hostname or u.fragment or u.username or u.password or u.port not in (None,443):
        raise ValueError('Invalid push endpoint URL')
    # Browsers use base64url encodings for these encryption keys.
    for k,lo,hi in [('p256dh',80,180),('auth',16,80)]:
        x=keys.get(k)
        if not isinstance(x,str) or not lo<=len(x)<=hi or not re.fullmatch('[A-Za-z0-9_-]+',x):
            raise ValueError('Invalid push keys')
    sid=subscription_id(endpoint)
    with db() as c:
        c.execute('INSERT OR REPLACE INTO subscriptions VALUES (?,?,?,?,?,NULL)',
                  (sid,endpoint,keys['p256dh'],keys['auth'],stamp()))
        c.execute('DELETE FROM subscriptions WHERE id NOT IN (SELECT id FROM subscriptions ORDER BY created_at DESC LIMIT 20)')
    return sid


def delete_subscription(endpoint):
    if not isinstance(endpoint,str):raise ValueError('Invalid endpoint')
    with db() as c:c.execute('DELETE FROM subscriptions WHERE id=?',(subscription_id(endpoint),))


def list_subscriptions():
    with db() as c:
        return [{'id':x[0],'endpoint':x[1],'keys':{'p256dh':x[2],'auth':x[3]}}
                for x in c.execute('SELECT id,endpoint,p256dh,auth FROM subscriptions').fetchall()]


def incident_list(limit=20):
    with db() as c:
        rows=c.execute('SELECT id,report_id,created_at,ack_at,notified_at FROM incidents ORDER BY created_at DESC LIMIT ?',
                       (max(1,min(limit,100)),)).fetchall()
    return [dict(zip(('id','report_id','created_at','ack_at','notified_at'),row)) for row in rows]


def ack_incident(incident_id):
    if not re.fullmatch('[0-9a-f]{24}',str(incident_id)):raise ValueError('Invalid incident id')
    with db() as c:
        result=c.execute('UPDATE incidents SET ack_at=COALESCE(ack_at,?) WHERE id=?',
                         (stamp(),incident_id))
        return result.rowcount>0
