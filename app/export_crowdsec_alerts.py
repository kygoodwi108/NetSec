#!/usr/bin/env python3
"""Convert local cscli alerts to non-secret bounded JSON consumed by NetSec."""
from pathlib import Path
import grp, datetime as dt, json, os, subprocess, tempfile

DEST=Path('/var/lib/server-status/crowdsec-alerts.json')

def export():
    result=subprocess.run(['/usr/bin/cscli','alerts','list','-o','json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=25,check=True)
    data=json.loads(result.stdout or b'[]')
    if data is None:data=[]
    if isinstance(data,dict):data=data.get('alerts') or data.get('items') or []
    if not isinstance(data,list):raise ValueError('Unknown cscli alerts JSON')
    out=[]
    for alert in data[:100]:
        if not isinstance(alert,dict):continue
        source=alert.get('source') if isinstance(alert.get('source'),dict) else {}
        out.append({'created_at':str(alert.get('created_at') or '')[:60],
                    'scenario':str(alert.get('scenario') or '')[:120],
                    'source':{'ip':str(source.get('ip') or source.get('value') or '')[:80],
                              'cn':str(source.get('cn') or source.get('country') or '')[:8]}})
    return out

def main():
    try:data=export()
    except Exception as exc:
        print('CrowdSec alert export unavailable:',type(exc).__name__,flush=True)
        raise SystemExit(1)
    DEST.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(dir=DEST.parent,prefix='.alerts-',suffix='.json')
    try:
        with os.fdopen(fd,'w') as f:
            json.dump(data,f); f.write('\n');f.flush();os.fsync(f.fileno())
        os.chown(name,0,grp.getgrnam('statusdash').gr_gid)
        os.chmod(name,0o640)
        os.replace(name,DEST)
    finally:
        if os.path.exists(name):os.unlink(name)
    print('Exported',len(data),'CrowdSec alert metadata records')

if __name__=='__main__':main()
