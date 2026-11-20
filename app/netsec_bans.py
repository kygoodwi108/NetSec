#!/usr/bin/env python3
"""NetSec 3.6 authenticated manual CrowdSec ban requests.

The unprivileged HTTP process can only enqueue a bounded, validated IP ban.
A separate root systemd service validates it independently and calls cscli.
"""
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import threading
import time

import netsec_intel as NI
import netsec_proxy_auth as NPA

BASE = Path(os.environ.get('NETSEC_BAN_DIR','/var/lib/server-status/ban-queue'))
REQUESTS = BASE / 'requests'
RESULTS = BASE / 'results'
DURATIONS = {'1h', '4h', '24h'}
MAX_PENDING = 10
_LOCK = threading.Lock()
UID_PROTECTED = set()


def public_ip(value):
    value = NI.canonical_ip(value)
    ip = ipaddress.ip_address(value)
    # Refuse private, local, documentation, multicast, reserved, and other
    # non-global addresses. Never allow CIDR/ranges/hostnames.
    if not ip.is_global:
        raise ValueError('Only one globally routable public IP can be banned')
    if value in NI.friendly_set():
        raise ValueError('This IP is confirmed friendly. Remove that label first, after verifying ownership.')
    return value


def _send(handler, code, data):
    body=json.dumps(data,ensure_ascii=False).encode('utf8')
    handler.send_response(code)
    for k,v in [('Content-Type','application/json; charset=utf-8'),('Content-Length',str(len(body))),
                ('Cache-Control','no-store'),('X-Content-Type-Options','nosniff'),
                ('Referrer-Policy','no-referrer')]: handler.send_header(k,v)
    handler.end_headers()
    handler.wfile.write(body)


def trigger(handler):
    if not NPA.require(handler,write=True): return
    try:
        length=int(handler.headers.get('Content-Length','0'))
        if not 2<=length<=600: raise ValueError('Invalid request length')
        obj=json.loads(handler.rfile.read(length).decode('utf8'))
        if not isinstance(obj,dict) or set(obj)-{'ip','duration'}: raise ValueError('Unsupported request fields')
        ip=public_ip(obj.get('ip'))
        duration=obj.get('duration')
        if duration not in DURATIONS: raise ValueError('Duration must be 1h, 4h, or 24h')
        with _LOCK:
            if not REQUESTS.is_dir() or not RESULTS.is_dir():
                raise RuntimeError('Manual-ban worker not configured; run the v3.6 installer')
            if len(list(REQUESTS.glob('*.json')))>=MAX_PENDING:
                return _send(handler,429,{'ok':False,'error':'Ban queue is full; check netsec-ban-worker service'})
            jobid=secrets.token_hex(12)
            job={'id':jobid,'ip':ip,'duration':duration,'created_at':dt.datetime.now(dt.timezone.utc).isoformat()}
            fd,tmp=tempfile.mkstemp(prefix='.new-',dir=REQUESTS)
            try:
                with os.fdopen(fd,'w',encoding='utf8') as f:
                    json.dump(job,f);f.flush();os.fsync(f.fileno())
                os.chmod(tmp,0o600)
                os.replace(tmp,REQUESTS/(jobid+'.json'))
            finally:
                if os.path.exists(tmp):os.unlink(tmp)
        return _send(handler,202,{'ok':True,'queued':True,'job_id':jobid,'ip':ip,'duration':duration,
                                'note':'Queued for CrowdSec; not enforced until worker confirms success and bouncer syncs.'})
    except (ValueError,TypeError,UnicodeError,json.JSONDecodeError) as exc:
        return _send(handler,400,{'ok':False,'error':str(exc)[:180]})
    except (OSError,RuntimeError):
        return _send(handler,503,{'ok':False,'error':'Ban queue unavailable; check systemd worker and permissions'})


def result(handler):
    if not NPA.require(handler,write=False): return
    from urllib.parse import parse_qs
    jobid=parse_qs(handler.path.partition('?')[2]).get('id',[''])[0]
    if not re.fullmatch(r'[a-f0-9]{24}',jobid):
        return _send(handler,400,{'ok':False,'error':'Invalid job identifier'})
    p=RESULTS/(jobid+'.json')
    try:
        if p.stat().st_size>3000:raise ValueError('Unexpected result')
        d=json.loads(p.read_text(encoding='utf8'))
        if isinstance(d,dict) and d.get('id')==jobid:return _send(handler,200,d)
    except (OSError,ValueError,TypeError):pass
    return _send(handler,200,{'ok':True,'state':'pending','id':jobid,
                              'note':'Awaiting validated CrowdSec decision from root worker'})
