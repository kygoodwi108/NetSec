#!/usr/bin/env python3
"""Deterministic, bounded, read-only checks that run BEFORE Jimmy writes a report.
No AI-generated shell commands. No credentials are sent, and request bodies are never included in reports.
"""
import collections
import datetime as dt
import gzip
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import time
from zoneinfo import ZoneInfo

import netsec_intel as NI

CONFIG_PATH=Path('/etc/netsec-diagnostics.json')
ERRORLOG=Path('/mnt/nginx-logs/error.log')
UTC=dt.timezone.utc
_CACHE={'at':0,'blocks':None}


def settings(path=CONFIG_PATH):
    try:
        if path.stat().st_size>12000:raise ValueError('Config too large')
        d=json.loads(path.read_text(encoding='utf8'))
        if not isinstance(d,dict):raise ValueError('Expected JSON settings')
        return d
    except (OSError,ValueError,TypeError):return {}


def _recent_lines(p, size=1500000):
    if not p.is_file():return []
    try:
        if p.suffix=='.gz':
            # Upper bound on expanded bytes; skip huge history rather than reading indefinitely.
            with gzip.open(p,'rb') as f: raw=f.read(size+1)
            if len(raw)>size:return []
        else:
            with p.open('rb') as f:
                f.seek(max(0,p.stat().st_size-size))
                raw=f.read(size)
        return raw.decode('utf8','replace').splitlines()
    except (OSError,EOFError,gzip.BadGzipFile):return []


def _errors(tz='America/Moncton', max_lines=60000):
    try:timezone=ZoneInfo(tz)
    except (KeyError,ValueError):timezone=UTC
    cutoff=dt.datetime.now(UTC)-dt.timedelta(hours=24)
    counts=collections.Counter();ups=collections.Counter()
    active_counts=collections.Counter();last_by_class={};first_by_class={};last_by_upstream={};first_by_upstream={};now_utc=dt.datetime.now(UTC)
    recent_cutoff=now_utc-dt.timedelta(minutes=15)
    recent_blocks={}; examined=0; readable=0
    for path in [ERRORLOG,ERRORLOG.with_name('error.log.1')]:
        lines=_recent_lines(path)
        if lines:readable+=1
        for line in lines[-max_lines:]:
            examined+=1
            m=re.match(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) ',line)
            if not m:continue
            try:at=dt.datetime.strptime(m.group(1),'%Y/%m/%d %H:%M:%S').replace(tzinfo=timezone).astimezone(UTC)
            except ValueError:continue
            if at<cutoff or at>dt.datetime.now(UTC)+dt.timedelta(minutes=5):continue
            # Classify each error once; preserve the 24h audit counts while
            # exposing genuinely recent activity and exact incident bounds.
            classes=[]
            if 'context: ngx.timer' in line and ('connection refused' in line or 'no route to host' in line):
                classes.append('crowdsec_timer_connectivity')
            if 'connect() failed' in line and 'while connecting to upstream' in line:
                classes.append('upstream_connection_failure')
            if 'upstream timed out' in line:classes.append('upstream_timeout')
            if 'no live upstreams' in line:classes.append('no_live_upstream')
            if 'upstream prematurely closed' in line:classes.append('upstream_closed')
            for cls in classes:
                first_by_class[cls]=min(first_by_class.get(cls,at),at)
                last_by_class[cls]=max(last_by_class.get(cls,at),at)
                if at>=recent_cutoff:active_counts[cls]+=1
            if any(cls!='crowdsec_timer_connectivity' for cls in classes):
                upstream_match=re.search(r'upstream: "(?:https?://)?([^/" ]+)',line)
                if upstream_match:
                    endpoint=upstream_match.group(1)[:70]
                    first_by_upstream[endpoint]=min(first_by_upstream.get(endpoint,at),at)
                    last_by_upstream[endpoint]=max(last_by_upstream.get(endpoint,at),at)
            if 'context: ngx.timer' in line and ('connection refused' in line or 'no route to host' in line):
                counts['crowdsec_timer_connectivity']+=1
            if 'connect() failed' in line and 'while connecting to upstream' in line:
                counts['upstream_connection_failure']+=1
            if 'upstream timed out' in line:counts['upstream_timeout']+=1
            if 'no live upstreams' in line:counts['no_live_upstream']+=1
            if 'upstream prematurely closed' in line:counts['upstream_closed']+=1
            if any(v in line for v in ('upstream_connection_failure', 'upstream timed out', 'no live upstreams', 'upstream prematurely closed')) or ('connect() failed' in line and 'while connecting to upstream' in line):
                x=re.search(r'upstream: "(?:https?://)?([^/" ]+)',line)
                if x:ups[x.group(1)[:70]]+=1
            if '[Crowdsec]' in line and "denied '" in line and '(by bouncer)' in line:
                x=re.search(r"denied '([^']+)' with '([^']+)'",line)
                if x:
                    try:ip=str(ipaddress.ip_address(x.group(1)))
                    except ValueError:continue
                    event=recent_blocks.setdefault(ip,{'ip':ip,'last_seen':at.isoformat(),'blocked_requests_sample':0,'action':x.group(2)[:20]})
                    event['blocked_requests_sample']+=1
                    event['last_seen']=max(event['last_seen'],at.isoformat())
    return {'source':'Nginx error.log and error.log.1, bounded tails','readable_files':readable,
            'lines_examined':examined,'time_window':'last_24h','class_counts':dict(counts),
            'recent_15m_class_counts':dict(active_counts),
            'first_seen_by_class':{k:v.isoformat() for k,v in first_by_class.items()},
            'last_seen_by_class':{k:v.isoformat() for k,v in last_by_class.items()},
            'first_seen_by_upstream':{k:v.isoformat() for k,v in first_by_upstream.items()},
            'last_seen_by_upstream':{k:v.isoformat() for k,v in last_by_upstream.items()},
            'upstreams':[{'address':addr,'errors':n} for addr,n in ups.most_common(8)],
            'observed_bouncer_denials':sorted(recent_blocks.values(),key=lambda v:v['last_seen'],reverse=True)[:16],
            'limits':'Nginx error logs do not prove every denied response was HTTP 403; rotated .gz files not sampled'}


def recent_bouncer_blocks():
    if _CACHE['blocks'] is not None and time.monotonic()-_CACHE['at']<90:
        return _CACHE['blocks']
    d=_errors(settings().get('nginx_timezone','America/Toronto'))
    _CACHE.update(at=time.monotonic(),blocks=d['observed_bouncer_denials'])
    return d['observed_bouncer_denials']


class RoutedHTTPS(http.client.HTTPSConnection):
    def __init__(self,hostname,origin_ip,timeout=3):
        super().__init__(hostname,443,timeout=timeout,context=ssl.create_default_context())
        self.origin_ip=origin_ip
    def connect(self):
        plain=socket.create_connection((self.origin_ip,443),timeout=self.timeout)
        self.sock=self._context.wrap_socket(plain,server_hostname=self.host)


def _probe(host,ip,path):
    conn=RoutedHTTPS(host,ip)
    try:
        conn.request('GET',path,headers={'User-Agent':'NetSec-Verification/3.6',
                                         'Accept':'text/html,*/*;q=0.8','Connection':'close'})
        r=conn.getresponse()
        body=r.read(8192)
        return {'http_status':r.status,'content_type':r.getheader('Content-Type','')[:65].split(';',1)[0].lower(),
                'sampled_bytes':len(body),'sample_digest':hashlib.sha256(body).hexdigest()[:24]}
    finally:conn.close()


def sensitive_http_checks(d):
    """Read-only approved sensitive-path checks.

    Default: legacy one-target/six-hour rotation. When the operator explicitly
    enables a source-allowlisted full scan, probe all configured targets in one
    pass. Only approved hosts at the configured private Nginx IP are contacted.
    """
    ip=d.get('nginx_host_ip');hosts=d.get('https_hosts') or []
    try:
        addr=ipaddress.ip_address(str(ip))
        if not addr.is_private:raise ValueError('Expected a private Nginx proxy address')
        if not isinstance(hosts,list) or not 1<=len(hosts)<=4:raise ValueError('Expected 1-4 hosts')
        hosts=[str(x).lower() for x in hosts]
        if any(not re.fullmatch(r'[a-z0-9.-]{3,100}',x) or x.startswith('.') or '..' in x for x in hosts):
            raise ValueError('Unsafe hostname')
    except (ValueError,TypeError):
        return {'state':'not_configured', 'details':'Set private nginx_host_ip and approved https_hosts in /etc/netsec-diagnostics.json'}
    targets=[(host,path) for host in hosts for path in ('/.env','/.git/config','/secrets.pkrvars.hcl')]
    cachefile=Path(os.environ.get('NETSEC_SENSITIVE_CHECK_CACHE','/var/lib/server-status/ai/sensitive-probes.json'))
    requested_mode=d.get('sensitive_probe_mode','rotating')
    approved=d.get('sensitive_probe_source_allowlisted') is True
    full=requested_mode=='full' and approved
    try:
        if full:
            # Zero means repeat at each scheduled AI run. One full run is still
            # bounded to the approved set of up to 12 paths plus baselines.
            gap=max(0,min(10080,int(d.get('sensitive_probe_full_interval_minutes',1440))))*60
        else:
            gap=max(6,min(168,int(d.get('sensitive_probe_gap_hours',6))))*3600
    except (TypeError,ValueError):gap=(86400 if full else 21600)
    try:
        if cachefile.stat().st_size>15000:raise ValueError('Cache size')
        cached=json.loads(cachefile.read_text(encoding='utf8'))
        if not isinstance(cached,dict):cached={}
    except (OSError,ValueError,TypeError):cached={}
    now=time.time()
    records=cached.get('results') if isinstance(cached.get('results'),dict) else {}
    records={k:v for k,v in records.items() if isinstance(v,dict) and
             isinstance(v.get('at_epoch'),(int,float)) and now-v['at_epoch']<=7*86400}
    last=float((cached.get('last_full_epoch') if full else cached.get('last_epoch')) or 0)
    performed=False
    attempted=0
    if now-last>=gap:
        selected=targets if full else [targets[int(cached.get('cursor') or 0)%len(targets)]]
        baselines={}
        for host,path in selected:
            key=host+' '+path
            try:
                if host not in baselines:
                    baselines[host]=_probe(host,str(addr),'/__netsec_readonly_404_probe_936712')
                res=_probe(host,str(addr),path);code=res['http_status']
                if code in (401,403,404):outcome='denied_or_missing'
                elif code==200 and res['content_type']=='text/html' and res['sample_digest']==baselines[host].get('sample_digest'):
                    outcome='frontend_fallback'
                elif 200<=code<300:outcome='requires_review'
                elif 300<=code<400:outcome='redirect_unresolved'
                else:outcome='unavailable'
                records[key]={'host':host,'path':path,'http_status':code,
                              'content_type':res['content_type'],'outcome':outcome,'at_epoch':now}
            except (OSError,ssl.SSLError,http.client.HTTPException) as exc:
                records[key]={'host':host,'path':path,'outcome':'unavailable',
                              'reason':type(exc).__name__,'at_epoch':now}
            attempted+=1
        performed=True
        cachefile.parent.mkdir(parents=True,exist_ok=True)
        cursor=(int(cached.get('cursor') or 0)+1)%len(targets) if not full else int(cached.get('cursor') or 0)%len(targets)
        obj={'last_epoch':now,'last_full_epoch':now if full else float(cached.get('last_full_epoch') or 0),
             'cursor':cursor,'results':records}
        fd,tmp=__import__('tempfile').mkstemp(dir=cachefile.parent,prefix='.v383-probe-',suffix='.json')
        try:
            with os.fdopen(fd,'w') as f:json.dump(obj,f)
            os.chmod(tmp,0o600)
            os.replace(tmp,cachefile)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    details=[dict(records[k]) for k in [h+' '+p for h,p in targets] if k in records]
    valid=sum(x['outcome'] in ('denied_or_missing','frontend_fallback') for x in details)
    review=sum(x['outcome'] in ('requires_review','redirect_unresolved') for x in details)
    unavailable=sum(x['outcome']=='unavailable' for x in details)
    covered=len(details)
    if full:
        mode_note=('Authorized full-scan mode: all '+str(len(targets))+' configured sensitive paths tested per scan when due; '
                   'source IP allowlisting is operator-attested, not verified by NetSec. '
                   'Full-scan interval '+str(gap//60)+' minutes (0 = each scheduled AI run). ')
    elif requested_mode=='full':
        mode_note=('Full-scan mode requested but NOT enabled: set sensitive_probe_source_allowlisted=true '
                   'only after verifying the actual Nginx client IP is allowlisted in CrowdSec. '
                   'Safe six-hour rotating mode remains active. ')
    else:
        mode_note='Rotating mode: one sensitive-path test every six hours or longer. '
    return {'state':'review' if review else 'verified' if covered==len(targets) and unavailable==0 else 'partial',
            'safe_or_fallback':valid,'requires_review':review,'unavailable':unavailable,
            'covered':covered,'total_targets':len(targets),'performed_this_run':performed,
            'attempted_this_run':attempted,'probe_mode':'full' if full else 'rotating',
            'next_test_earliest':dt.datetime.fromtimestamp((now if performed else last)+gap,UTC).isoformat(),
            'results':details,
            'limits':mode_note+'Cached results may be up to seven days old; HTTP status alone never proves '
                     'secret disclosure, and 403 could originate from the bouncer. No redirects, credentials, '
                     'or persistent response bodies.'}


def collect(status=None,config=None):
    d=settings();now=dt.datetime.now(UTC).isoformat()
    try:errors=_errors(d.get('nginx_timezone','America/Moncton'))
    except Exception as exc:errors={'state':'unavailable','reason':type(exc).__name__}
    enforcement=(status or {}).get('enforcement') or NI.read_enforcement()
    active=enforcement.get('state')=='active'
    denials=errors.get('observed_bouncer_denials') or []
    checks=[
      {'id':'crowdsec_enforcement','state':'verified' if active and denials else 'partial' if active else 'unavailable',
       'result':('CrowdSec bouncer is pulling and '+str(len(denials))+' distinct IPs have recent Nginx ban-denial log entries'
                 if active and denials else 'Bouncer reports recent API pulls; no recent denial event to independently corroborate'
                 if active else 'Fresh bouncer API-pull evidence unavailable'),
       'limits':'No synthetic hostile-source 403 test is performed automatically; source IP cannot be spoofed by a simple request'},
      {'id':'nginx_upstreams','state':'verified' if errors.get('readable_files',0)>0 else 'unavailable',
       'result':'Last 24h bounded Nginx error-log classes: '+str(errors.get('class_counts',{}))+'. Top failing upstreams: '+str(errors.get('upstreams',[])[:4]),
       'limits':'Counts are from bounded log tails, not all historical files'},
    ]
    try:sensitive=sensitive_http_checks(d)
    except Exception as exc:sensitive={'state':'unavailable','reason':type(exc).__name__}
    checks.append({'id':'sensitive_paths','state':sensitive.get('state','unavailable'),
                   'result':'Sensitive-path HTTPS checks: '+str(sensitive.get('covered',0))+'/'+str(sensitive.get('total_targets',0))+' targets covered, '+str(sensitive.get('safe_or_fallback',0))+' denied/missing or fallback, '
                       +str(sensitive.get('requires_review',0))+' review, '+str(sensitive.get('unavailable',0))+' unavailable',
                   'limits':sensitive.get('limits','No live checks performed')})
    return {'generated_at':now,'mode':'predefined read-only checks, no model-generated code or remediations',
            'checks':checks,'sensitive_path_details':(sensitive.get('results') or [])[:12],
            'nginx_error_summary':{k:errors.get(k) for k in ('readable_files','class_counts','recent_15m_class_counts','first_seen_by_class','last_seen_by_class','first_seen_by_upstream','last_seen_by_upstream','upstreams','observed_bouncer_denials')},
            'enforcement_note':'Successful cscli decision + current bouncer pull does not independently prove HTTP 403 without an observed controlled test'}
