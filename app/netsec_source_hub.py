#!/usr/bin/env python3
"""NetSec 3.8 source intelligence: bounded observations plus local AI metadata.

AI labels never affect CrowdSec decisions or mark a source confirmed friendly.
Manual labels always win. IP observations derive solely from existing read-only logs.
"""
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
from contextlib import closing

import netsec_connections as NC
import netsec_intel as NI

STATE_DIR = Path(os.environ.get('NETSEC_INTEL_DIR', '/var/lib/server-status/intel'))
AI_DB = STATE_DIR / 'source-ai-v38.sqlite3'
AI_STATE = STATE_DIR / 'source-ai-v38-state.json'
AI_CLASSES = frozenset(('routine','scanner','suspicious','hostile','unknown'))
MANUAL_CLASSES = frozenset(('friendly','hostile','watch','routine','scanner','suspicious','unknown'))
ORDER = ('requests_desc','requests_asc','suspicion_desc','unclassified','last_seen')
FILTER = ('all','trusted','unreviewed','ai_labeled','manual','suspicious','low_volume')
UTC = dt.timezone.utc


def _now():
    return dt.datetime.now(UTC).isoformat()


def _conn():
    STATE_DIR.mkdir(parents=True,exist_ok=True,mode=0o750)
    db = sqlite3.connect(str(AI_DB),timeout=10)
    db.execute('PRAGMA busy_timeout=10000')
    db.execute('''CREATE TABLE IF NOT EXISTS source_labels (
        ip TEXT PRIMARY KEY, label TEXT NOT NULL, confidence TEXT NOT NULL,
        reason TEXT NOT NULL, assessed_at TEXT NOT NULL, evidence_hash TEXT NOT NULL)''')
    return db


def stored_ai():
    if not AI_DB.exists():
        return {}
    with closing(_conn()) as db:
        rows = db.execute('SELECT ip,label,confidence,reason,assessed_at,evidence_hash FROM source_labels').fetchall()
    return {ip:{'label':label,'confidence':confidence,'reason':reason,'assessed_at':ts,'evidence_hash':digest}
            for ip,label,confidence,reason,ts,digest in rows}


def store_ai(records):
    """Only from a validated local AI response. Never writes operator metadata."""
    if not records: return 0
    prepared=[]
    ts=_now()
    for r in records:
        ip=NI.canonical_ip(r['ip'])
        label=r['label']
        if label not in AI_CLASSES:raise ValueError('Invalid AI label')
        confidence=r['confidence']
        if confidence not in ('low','medium','high'):raise ValueError('Invalid AI confidence')
        reason=r['reason']
        if not isinstance(reason,str) or len(reason)>220:raise ValueError('Invalid AI rationale')
        digest=r['evidence_hash']
        if not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('Invalid evidence hash')
        prepared.append((ip,label,confidence,reason,ts,digest))
    with closing(_conn()) as db:
        with db:
            db.executemany('''INSERT INTO source_labels(ip,label,confidence,reason,assessed_at,evidence_hash)
           VALUES(?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET label=excluded.label,
           confidence=excluded.confidence, reason=excluded.reason,
           assessed_at=excluded.assessed_at, evidence_hash=excluded.evidence_hash''',prepared)
    return len(prepared)


def _cached_stats(files, lines, parse):
    """Use the existing 90-second bounded connections scan shared with the dashboard."""
    import time
    with NC._LOCK:
        if NC._CACHE['stats'] is None or time.monotonic()-NC._CACHE['at']>=NC.CACHE_SECONDS:
            result=NC.collect(files,lines,parse)
            NC._CACHE.update(stats=result,at=time.monotonic())
        return NC._CACHE['stats']


def _risk(counts):
    # Sorting hint only; not a security verdict.
    return (int(counts.get('probe_2xx',0))*12 + int(counts.get('probe_like',0))*5
            + int(counts.get('denied_401_403',0))*2 + min(20,int(counts.get('http_5xx',0))))


def _evidence(stats, window='7d'):
    out=[]
    for ip,item in stats['by_ip'].items():
        counts=dict(item['windows'].get(window,{}))
        if not counts.get('requests',0): continue
        out.append({'ip':ip,'requests':int(counts.get('requests',0)),
                    'probe_like':int(counts.get('probe_like',0)),
                    'probe_2xx':int(counts.get('probe_2xx',0)),
                    'denied_401_403':int(counts.get('denied_401_403',0)),
                    'not_found_404':int(counts.get('not_found_404',0)),
                    'http_5xx':int(counts.get('http_5xx',0)),
                    'http_2xx':int(counts.get('http_2xx',0)),
                    'last_seen':item['last_seen'].isoformat(),
                    'top_paths':[{'path':str(p)[:110], 'requests':int(c)}
                                 for p,c in item['top_paths'].most_common(5)],
                    'suspicion':_risk(counts)})
    return out


def evidence_for_worker(files,lines,parse):
    return _evidence(_cached_stats(files,lines,parse),'7d')


def state_info():
    try:
        if AI_STATE.stat().st_size>8000:raise ValueError('oversized state')
        obj=json.loads(AI_STATE.read_text(encoding='utf8'))
        return {k:obj.get(k) for k in ('at','state','processed','pending','error','model')}
    except (OSError,ValueError,TypeError):
        return {'state':'not_run'}


def status_update(data):
    STATE_DIR.mkdir(parents=True,exist_ok=True,mode=0o750)
    from tempfile import NamedTemporaryFile
    with NamedTemporaryFile(mode='w',encoding='utf8',dir=STATE_DIR,prefix='.source-ai-',delete=False) as f:
        name=f.name
        try:
            json.dump({'at':_now(),**data},f,separators=(',',':'))
            f.flush();os.fsync(f.fileno())
        except Exception:
            os.unlink(name);raise
    os.chmod(name,0o640)
    os.replace(name,AI_STATE)


def inventory(files, lines, parse, country, params):
    """Paginate all observed addresses, even one-hit sources; no classification threshold."""
    window=params.get('window',['24h'])[0]
    order=params.get('sort',['requests_desc'])[0]
    filt=params.get('filter',['all'])[0]
    term=params.get('search',[''])[0].strip().lower()
    if window not in NC.WINDOWS or order not in ORDER or filt not in FILTER or len(term)>80:
        raise ValueError('Unsupported source hub query')
    try:limit=int(params.get('limit',['100'])[0]);offset=int(params.get('offset',['0'])[0])
    except (TypeError,ValueError):raise ValueError('Invalid paging parameters') from None
    if limit<1 or limit>200 or offset<0 or offset>25000:raise ValueError('Paging out of range')
    stats=_cached_stats(files,lines,parse)
    manual=NI.read_registry().get('addresses',{})
    ai=stored_ai()
    rows=[]
    for row in _evidence(stats,window):
        ip=row['ip'];m=manual.get(ip) or {}; a=ai.get(ip) or {}
        effective=m.get('status') or a.get('label') or 'pending'
        origin='manual' if m.get('status') else 'ai' if a.get('label') else 'pending'
        row.update({'label':effective,'source':origin,
                    'friendly':effective=='friendly',
                    'manual_label':m.get('label','') if m else '',
                    'ai_label':a.get('label',''),
                    'confidence':a.get('confidence',''),
                    'reason':a.get('reason','') if origin=='ai' else (m.get('note') or ''),
                    'assessed_at':a.get('assessed_at')})
        if term and term not in (ip+' '+str(row.get('manual_label',''))).lower():continue
        if filt=='trusted' and effective!='friendly':continue
        if filt=='unreviewed' and origin!='pending':continue
        if filt=='ai_labeled' and origin!='ai':continue
        if filt=='manual' and origin!='manual':continue
        if filt=='suspicious' and not (row['suspicion'] or effective in ('scanner','suspicious','hostile')):continue
        if filt=='low_volume' and row['requests']>=100:continue
        rows.append(row)
    if order=='requests_desc':rows.sort(key=lambda r:(-r['requests'],-r['suspicion'],r['ip']))
    elif order=='requests_asc':rows.sort(key=lambda r:(r['requests'],-r['suspicion'],r['ip']))
    elif order=='suspicion_desc':rows.sort(key=lambda r:(-r['suspicion'],-r['requests'],r['ip']))
    elif order=='last_seen':rows.sort(key=lambda r:(r['last_seen'],r['requests']),reverse=True)
    else:rows.sort(key=lambda r:(0 if r['source']=='pending' else 1,r['requests'],r['ip']))
    total=len(rows);page=rows[offset:offset+limit]
    for r in page:
        r['country']=country(r['ip'])
        # Keep the API response bounded; worker collects evidence independently.
        r['top_paths']=r['top_paths'][:3]
    return {'ok':True,'window':window,'sort':order,'filter':filt,'offset':offset,
            'limit':limit,'total':total,'next_offset':offset+len(page) if offset+len(page)<total else None,
            'observed':len(stats['by_ip']),'ai_state':state_info(),
            'coverage':{'log_files':stats['log_files'],'warnings':stats['errors'][:5],
                        'limited_to_bounded_logs':True,'max_observed_ips':NC.MAX_IPS,
                        'note':'All IPs in the bounded available Nginx log sample. Not all historical network connections.'},
            'rows':page}
