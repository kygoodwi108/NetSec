#!/usr/bin/env python3
"""Root-only, systemd-activated CrowdSec ban executor. No shell=True or network commands."""
import datetime as dt
import grp
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import pwd

BASE=Path('/var/lib/server-status/ban-queue')
REQUESTS=BASE/'requests'
RESULTS=BASE/'results'
DURATIONS={'1h','4h','24h'}

def emit(path,obj):
    fd,tmp=tempfile.mkstemp(prefix='.result-',dir=RESULTS)
    try:
        with os.fdopen(fd,'w') as f:
            json.dump(obj,f);f.write('\n');f.flush();os.fsync(f.fileno())
        os.chmod(tmp,0o600)
        os.chown(tmp,pwd.getpwnam('statusdash').pw_uid,grp.getgrnam('statusdash').gr_gid)
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def process(jobfile):
    jobid=jobfile.stem
    if not re.fullmatch(r'[a-f0-9]{24}',jobid):return
    result={'ok':False,'state':'failed','id':jobid}
    try:
        if jobfile.is_symlink() or jobfile.stat().st_size>1200:raise ValueError('Unsafe job file')
        job=json.loads(jobfile.read_text(encoding='utf8'))
        if not isinstance(job,dict) or set(job)!={'id','ip','duration','created_at'}:raise ValueError('Invalid job')
        if job['id']!=jobid or job['duration'] not in DURATIONS:raise ValueError('Invalid job arguments')
        ip=str(ipaddress.ip_address(str(job['ip'])))
        if ip!=job['ip'] or not ipaddress.ip_address(ip).is_global:raise ValueError('Only global IP addresses')
        age=dt.datetime.now(dt.timezone.utc)-dt.datetime.fromisoformat(job['created_at'])
        if not dt.timedelta(0)<=age<=dt.timedelta(minutes=3):raise ValueError('Stale request')
        # Recheck operator-confirmed trusted IPs, even if a previous HTTP validation passed.
        import netsec_intel
        if ip in netsec_intel.friendly_set():raise ValueError('Refusing confirmed-friendly IP')
        cmd=['/usr/bin/cscli','decisions','add','--ip',ip,'--duration',job['duration'],
             '--type','ban','--reason','netsec-manual-dashboard']
        cp=subprocess.run(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,timeout=25,check=False,text=True)
        if cp.returncode!=0:
            # Don't copy arbitrary CLI output back to browser.
            raise RuntimeError('CrowdSec rejected the request (exit '+str(cp.returncode)+')')
        result={'ok':True,'state':'added','id':jobid,'ip':ip,'duration':job['duration'],
                'note':'Decision added to CrowdSec LAPI. Nginx stream bouncer may require its next pull.'}
    except (ValueError,TypeError,KeyError,RuntimeError,subprocess.TimeoutExpired,OSError) as exc:
        result['error']=str(exc)[:140]
    finally:
        jobfile.unlink(missing_ok=True)
        result['completed_at']=dt.datetime.now(dt.timezone.utc).isoformat()
        emit(RESULTS/(jobid+'.json'),result)

def main():
    if os.geteuid()!=0:raise SystemExit('Root required')
    for p in sorted(REQUESTS.glob('*.json'))[:20]:process(p)
    # Keep at most 24h of per-job results; never retain arbitrary operator requests.
    for p in RESULTS.glob('*.json'):
        try:
            if time.time()-p.stat().st_mtime>86400:p.unlink()
        except OSError:pass
if __name__=='__main__':main()
