#!/usr/bin/env python3
"""Export non-secret CrowdSec enforcement posture for NetSec; run as root in the NetSec LXC.
No bouncer keys, credentials or raw request bodies ever exported.
"""
import datetime as dt
import json
import os
import pathlib
import subprocess
import tempfile

DEST=pathlib.Path('/var/lib/server-status/crowdsec-enforcement.json')

def call(kind):
    cmd=['/usr/bin/cscli',kind,'list','-o','json']
    result=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=18,check=True)
    raw=json.loads(result.stdout or b'[]')
    if raw is None:return []
    if isinstance(raw,list):return raw
    if isinstance(raw,dict):
        for field in ('items','data','bouncers','decisions'):
            if isinstance(raw.get(field),list):return raw[field]
    raise ValueError(f'Unexpected {kind} JSON format')

def safe(x,n=120):return str(x or '')[:n]

def first(item,*keys):
    for k in keys:
        if item.get(k) is not None:return item[k]
    return None

def main():
    now=dt.datetime.now(dt.timezone.utc)
    obj={'updated_at':now.isoformat(),'state':'unavailable','bouncers':[],'decisions':[]}
    try:
        b=call('bouncers');d=call('decisions')
        for item in b[:30]:
            if not isinstance(item,dict):continue
            obj['bouncers'].append({
                'name':safe(first(item,'name','Name'),80),
                'valid':(not bool(item['revoked']) if 'revoked' in item else str(first(item,'valid','Valid') or '').lower() in ('true','yes','✓','1')),
                'last_pull':safe(first(item,'last_pull','last_api_pull','LastPull','last_pull_at','last_pull_time'),50),
                'ip_address':safe(first(item,'ip_address','ip','IpAddress'),60)})
        for item in d[:200]:
            if not isinstance(item,dict):continue
            obj['decisions'].append({
                'scope':safe(first(item,'scope','Scope'),15),
                'value':safe(first(item,'value','Value'),80),
                'type':safe(first(item,'type','Type'),30),
                'reason':safe(first(item,'scenario','reason','Reason'),100),
                'duration':safe(first(item,'duration','Duration','expiration'),50)})
        obj['state']='registered' if obj['bouncers'] else 'no_bouncer'
        # A registered bouncer is not necessarily connected. Recent LAPI pull is the stronger evidence.
        if obj['bouncers']:
            active=False
            for x in obj['bouncers']:
                if not x['valid'] or not x['last_pull']:continue
                try:
                    last=dt.datetime.fromisoformat(x['last_pull'].replace('Z','+00:00'))
                    active|=last.tzinfo is not None and (now-last.astimezone(dt.timezone.utc)).total_seconds()<300
                except ValueError:pass
            if active:obj['state']='active'
        obj['active_decision_count']=len(obj['decisions'])
    except (subprocess.SubprocessError,ValueError,TypeError) as e:
        obj['error']=type(e).__name__
    fd,name=tempfile.mkstemp(dir=DEST.parent,prefix='.crowdsec-tmp-',suffix='.json')
    try:
        with os.fdopen(fd,'w') as f:
            json.dump(obj,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
        os.chmod(name,0o640)
        os.chown(name,0,__import__('grp').getgrnam('statusdash').gr_gid)
        os.replace(name,DEST)
    finally:
        if os.path.exists(name):os.unlink(name)
    print('CrowdSec enforcement export:',obj['state'],obj.get('active_decision_count','unknown'),'decisions')

if __name__=='__main__':main()
