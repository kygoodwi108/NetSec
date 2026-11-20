#!/usr/bin/env python3
"""NetSec v3: IP labels, operator-reviewed suggestions, and a durable AI journal.
Pure stdlib, local-only state. A friendly label changes display filtering, never CrowdSec enforcement.
"""
import argparse
import datetime as dt
import hmac
import ipaddress
import json
import os
import pathlib
import secrets
import sqlite3
import tempfile
from contextlib import closing

ROOT = pathlib.Path(os.environ.get('NETSEC_INTEL_DIR','/var/lib/server-status/intel'))
REGISTRY = ROOT/'ip-metadata.json'
DB = ROOT/'history.sqlite3'
ADMIN_TOKEN = pathlib.Path(os.environ.get('NETSEC_INTEL_TOKEN_FILE','/etc/netsec-intel-admin.token'))
UTC=dt.timezone.utc

def stamp(): return dt.datetime.now(UTC).isoformat()

def canonical_ip(value):
    try: return str(ipaddress.ip_address(str(value)))
    except (ValueError,TypeError): raise ValueError('Expected a single valid IPv4 or IPv6 address') from None

def ensure_root():
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o750)

def read_registry():
    try:
        if REGISTRY.stat().st_size > 120_000: raise ValueError('Metadata file too large')
        d=json.loads(REGISTRY.read_text(encoding='utf-8'))
        if not isinstance(d,dict) or not isinstance(d.get('addresses',{}),dict): raise ValueError('Bad metadata schema')
        return d
    except FileNotFoundError: return {'version':1,'updated_at':None,'addresses':{}}

def write_json_atomic(path, data):
    ensure_root()
    fd,name=tempfile.mkstemp(dir=ROOT,prefix='.tmp-',suffix='.json')
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            json.dump(data,f,indent=2,ensure_ascii=False)
            f.write('\n'); f.flush(); os.fsync(f.fileno())
        os.chmod(name,0o640)
        os.replace(name,path)
    finally:
        if os.path.exists(name): os.unlink(name)

def set_label(ip,status,label='',note=''):
    ip=canonical_ip(ip)
    if status not in ('friendly','hostile','watch','routine','scanner','suspicious','unknown'): raise ValueError('Status must be friendly, hostile, watch, routine, scanner, suspicious or unknown')
    if not isinstance(label,str) or not isinstance(note,str) or len(label)>80 or len(note)>180:
        raise ValueError('Label or note invalid/too long')
    d=read_registry()
    if status=='unknown':
        d['addresses'].pop(ip,None)
    else:
        d['addresses'][ip]={'status':status,'label':label.strip() or ip,'note':note.strip(),
                            'confirmed_at':stamp(),'confirmed_by':'operator'}
    d['updated_at']=stamp()
    write_json_atomic(REGISTRY,d)
    return d['addresses'].get(ip)

def friendly_set(registry=None):
    d=registry if registry is not None else read_registry()
    return {ip for ip,obj in d.get('addresses',{}).items() if obj.get('status')=='friendly'}

def check_token(input_token):
    if not isinstance(input_token,str) or len(input_token)>200: return False
    try:
        token=ADMIN_TOKEN.read_text(encoding='ascii').strip()
        return len(token)>=32 and hmac.compare_digest(input_token,token)
    except OSError: return False

def build_candidates(all_traffic,registry,alerts):
    existing=registry.get('addresses',{})
    alerted={str(a.get('source_ip')) for a in alerts if isinstance(a,dict)}
    out=[]
    for entry in all_traffic.get('top_ips',[])[:30]:
        ip=entry.get('ip','')
        if ip in existing: continue
        n=int(entry.get('requests',0))
        probes={e['ip']:int(e.get('requests',0)) for e in all_traffic.get('probe_sources',[])}.get(ip,0)
        # Conservatively suggest, NEVER approve. High-volume attacks can resemble normal traffic.
        if n >= 100 and probes == 0 and ip not in alerted:
            out.append({'ip':ip,'requests_24h':n,'reason':'High repeat volume, no recognised probe paths; identity unverified',
                        'status':'review','confidence':'low'})
    return out[:12]

def history_db():
    ensure_root()
    db=sqlite3.connect(str(DB),timeout=6)
    db.execute('PRAGMA busy_timeout=5000')
    db.execute('''CREATE TABLE IF NOT EXISTS assessments (
        generated_at TEXT PRIMARY KEY, severity TEXT NOT NULL, summary TEXT NOT NULL,
        traffic_risk TEXT, requests24 INTEGER, probes24 INTEGER, errors24 INTEGER,
        unknown_ips24 INTEGER, model TEXT, payload TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS ip_observations (
        generated_at TEXT NOT NULL, ip TEXT NOT NULL, requests24 INTEGER NOT NULL,
        PRIMARY KEY(generated_at,ip))''')
    db.execute('CREATE INDEX IF NOT EXISTS idx_obs_ip ON ip_observations(ip,generated_at)')
    return db

def record_assessment(report, telemetry):
    if report.get('state')!='ready': return
    generated_at=str(report.get('updated_at') or stamp())
    now=dt.datetime.now(UTC)
    cutoff=(now-dt.timedelta(days=90)).isoformat()
    # Assessed metrics are rolling 24h windows, NOT separate 10-minute event counts.
    with closing(history_db()) as db:
        with db:
            db.execute('''INSERT OR REPLACE INTO assessments
              (generated_at,severity,summary,traffic_risk,requests24,probes24,errors24,unknown_ips24,model,payload)
              VALUES (?,?,?,?,?,?,?,?,?,?)''',(
                  generated_at,report.get('severity','unknown'),report.get('summary','')[:450],
                  str(telemetry.get('traffic_heuristic_risk',{}).get('level','unknown')),
                  int(telemetry.get('requests_24h') or 0),int(telemetry.get('probes_24h') or 0),
                  int(telemetry.get('http_5xx_24h') or 0),int(telemetry.get('unique_ips_24h') or 0),
                  str(report.get('model',''))[:80],json.dumps(report,ensure_ascii=False)[:8000]))
            for r in telemetry.get('top_ips',[])[:20]:
                try: ip=canonical_ip(r.get('ip'))
                except ValueError:continue
                db.execute('INSERT OR REPLACE INTO ip_observations VALUES (?,?,?)',(
                    generated_at,ip,int(r.get('requests') or 0)))
            db.execute('DELETE FROM assessments WHERE generated_at < ?', (cutoff,))
            db.execute('DELETE FROM ip_observations WHERE generated_at < ?', (cutoff,))

def history_view(limit=45):
    limit=max(1,min(int(limit),180))
    if not DB.exists(): return []
    with closing(history_db()) as db:
        rows=db.execute('''SELECT generated_at,severity,summary,requests24,probes24,errors24,unknown_ips24
            FROM assessments ORDER BY generated_at DESC LIMIT ?''',(limit,)).fetchall()
    return [dict(zip(('at','severity','summary','requests24','probes24','errors24','unknown_ips24'),r)) for r in rows]

def model_history_context():
    if not DB.exists(): return {'previous_assessments':[],'recurring_sources':[]}
    cutoff=(dt.datetime.now(UTC)-dt.timedelta(days=7)).isoformat()
    with closing(history_db()) as db:
        recent=db.execute('''SELECT generated_at,severity,summary,requests24,probes24 FROM assessments
                              WHERE generated_at >= ? ORDER BY generated_at DESC LIMIT 8''',(cutoff,)).fetchall()
        recurring=db.execute('''SELECT ip,COUNT(*) AS samples,MAX(generated_at) AS last_seen
           FROM ip_observations WHERE generated_at >= ? GROUP BY ip
           ORDER BY samples DESC LIMIT 12''',(cutoff,)).fetchall()
    return {'previous_assessments':[{'at':r[0],'severity':r[1],'summary':r[2][:220],
                                     'rolling_24h_requests':r[3],'rolling_24h_probes':r[4]} for r in recent],
            'recurring_sources':[{'ip':r[0],'assessment_snapshots_seen':r[1], 'last_seen':r[2]}
                                 for r in recurring],
            'warning':'Each snapshot covers overlapping rolling 24-hour windows; never sum them as unique events.'}

def read_enforcement():
    path=pathlib.Path('/var/lib/server-status/crowdsec-enforcement.json')
    try:
        if path.stat().st_size>180_000:raise ValueError('Enforcement export is too large')
        obj=json.loads(path.read_text(encoding='utf8'))
        if not isinstance(obj,dict):raise ValueError('Bad enforcement export')
        last=dt.datetime.fromisoformat(str(obj.get('updated_at','')).replace('Z','+00:00'))
        if last.tzinfo is None or (dt.datetime.now(UTC)-last.astimezone(UTC)).total_seconds()>210:
            return {'state':'stale','note':'CrowdSec exporter is not refreshing'}
        state=obj.get('state','unavailable')
        if state not in ('active','no_bouncer','registered','unavailable'):state='unavailable'
        return {'state':state, 'bouncers':obj.get('bouncers',[])[:15],
                'active_decision_count':int(obj.get('active_decision_count') or 0),
                'decisions':obj.get('decisions',[])[:75],
                'updated_at':obj.get('updated_at'),
                'note':'Active means a registered bouncer pulled recently; enforcement effectiveness still requires a real HTTP test.'}
    except (OSError,ValueError,TypeError):
        return {'state':'unavailable','note':'No readable CrowdSec enforcement export'}

def public_metadata(scope,all_data,unknown_data):
    registry=read_registry()
    addresses=registry.get('addresses',{})
    all_traffic=all_data.get('traffic') or {}
    unknown_traffic=unknown_data.get('traffic') or {}
    return {
        'scope':scope,'trusted_count':len(friendly_set(registry)),
        'all_requests24':all_traffic.get('requests',0),
        'unknown_requests24':unknown_traffic.get('requests',0),
        'friendly_requests24':max(0,int(all_traffic.get('requests',0))-int(unknown_traffic.get('requests',0))),
        'updated_at':registry.get('updated_at'),
        'addresses':[{'ip':ip,**obj} for ip,obj in sorted(addresses.items())][:150],
        'review_candidates':build_candidates(all_traffic,registry,(all_data.get('crowdsec') or {}).get('alerts') or []),
        'history':history_view(42),
        'meaning':'Friendly means operator-confirmed; it affects dashboard traffic scope and AI context only. It never removes CrowdSec decisions.'
    }

if __name__=='__main__':
    p=argparse.ArgumentParser(description='NetSec operator-managed IP metadata (single IP only)')
    sub=p.add_subparsers(dest='cmd',required=True)
    a=sub.add_parser('mark');a.add_argument('ip');a.add_argument('status',choices=['friendly','watch','unknown']);
    a.add_argument('label',nargs='?',default='');a.add_argument('--note',default='')
    sub.add_parser('list')
    args=p.parse_args()
    if args.cmd=='mark': print(json.dumps(set_label(args.ip,args.status,args.label,args.note),indent=2))
    else:print(json.dumps(read_registry(),indent=2))
