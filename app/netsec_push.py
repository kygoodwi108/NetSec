#!/usr/bin/env python3
"""Opt-in Web Push for new, evidence-calibrated red incidents.

Web push uses pywebpush 2.5.0 in an isolated venv, optional during installation.
Payload contains only severity and generic text, never IPs/logs/AI content.
"""
import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
import subprocess
from urllib.parse import urlsplit

import netsec_jimmy_store as STORE

CONFIG=Path('/etc/netsec-push.json')
REPORT=Path('/var/lib/server-status/ai/latest.json')


def config():
    try:
        cfg=json.loads(CONFIG.read_text())
        p=urlsplit(cfg['origin'])
        if p.scheme!='https' or not p.hostname or p.username or p.password or p.path not in ('','/') or p.query:
            raise ValueError('Invalid push origin')
        if not cfg['subject'].startswith('mailto:') or '@' not in cfg['subject']:
            raise ValueError('Invalid VAPID contact')
        if not cfg['public_key'] or not Path(cfg['private_key_path']).is_file():
            raise ValueError('VAPID keys unavailable')
        return cfg
    except (OSError,ValueError,KeyError,TypeError):return None


def allowed_endpoint(endpoint):
    try:
        p=urlsplit(endpoint)
        host=(p.hostname or '').lower()
        if p.scheme!='https' or p.username or p.password or p.port not in (None,443) or p.fragment or not p.path:
            return False
        try:
            ipaddress.ip_address(host)
            return False
        except ValueError:pass
        allow_exact={'fcm.googleapis.com','updates.push.services.mozilla.com','web.push.apple.com'}
        allow_suffix=('.push.apple.com','.push.services.mozilla.com','.notify.windows.com')
        return host in allow_exact or any(host.endswith(s) for s in allow_suffix)
    except (ValueError,TypeError,AttributeError):return False


def status():
    cfg=config()
    return {'ok':True,'enabled':bool(cfg),'public_key':cfg.get('public_key') if cfg else '',
            'subscribers':len(STORE.list_subscriptions()) if cfg else 0,
            'quiet_until':STORE.get_kv('quiet_until',''),
            'escalation_after_hours':int(STORE.get_kv('escalation_after_hours','0') or 0),
            'incidents':STORE.incident_list(12)}


class PushGone(RuntimeError):
    pass


def send_push(subscription,data):
    if not allowed_endpoint(subscription['endpoint']):raise ValueError('Unrecognized browser push endpoint')
    cfg=config()
    if not cfg:raise ValueError('Push not enabled')
    # The dashboard uses Debian's stdlib Python, while pywebpush lives in an
    # isolated venv. Never expose subscription keys or endpoints in process args.
    child=subprocess.run(['/opt/netsec-push-venv/bin/python',str(Path(__file__).resolve()),'--send-one'],
                         input=json.dumps({'subscription':subscription,'payload':data}),text=True,
                         stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20,check=False)
    if child.returncode==44:raise PushGone('Browser subscription expired')
    if child.returncode:raise RuntimeError('Push delivery failed')


def _send_one():
    # Invoked only by the server's own statusdash process; stdin is private.
    obj=json.load(sys.stdin)
    sub=obj['subscription'];data=obj['payload']
    if not allowed_endpoint(sub['endpoint']):raise ValueError('Invalid destination')
    cfg=config()
    if not cfg:raise ValueError('VAPID unavailable')
    from pywebpush import webpush
    try:
        webpush(subscription_info={'endpoint':sub['endpoint'],'keys':sub['keys']},
                data=json.dumps(data,separators=(',',':')),
                vapid_private_key=cfg['private_key_path'],vapid_claims={'sub':cfg['subject']},ttl=300,timeout=12)
    except Exception as ex:
        # A 404/410 means the browser invalidated this endpoint. Do not leak
        # the full endpoint or push credentials into service logs.
        if getattr(getattr(ex,'response',None),'status_code',None) in (404,410):
            raise SystemExit(44)
        raise SystemExit(1)


def deliver(data):
    delivered,failures=0,0
    for subscription in STORE.list_subscriptions():
        try:
            send_push(subscription,data)
            delivered+=1
            with STORE.db() as c:
                c.execute('UPDATE subscriptions SET last_success=? WHERE id=?',(STORE.stamp(),subscription['id']))
        except Exception as ex:
            failures+=1
            status=410 if isinstance(ex,PushGone) else None
            if isinstance(ex,PushGone):
                with STORE.db() as c:c.execute('DELETE FROM subscriptions WHERE id=?',(subscription['id'],))
            # No URL, device key or credential is logged.
            print('Push delivery failure:',type(ex).__name__,'http',status,file=sys.stderr)
    return delivered,failures


def event_fingerprint(report):
    risk=report.get('risk_assessment') or {}
    if report.get('state')!='ready' or report.get('severity')!='red' or risk.get('severity')!='red':return None
    if 'deterministic cross-check' not in str(risk.get('method','')):return None
    reasons=risk.get('reasons') or []
    if not isinstance(reasons,list) or not reasons:return None
    # Ignore rolling numeric counts and message wording to avoid a new event
    # on every 10-minute assessment of the same continuing incident.
    canonical=[re.sub(r'\d+', '#',str(reason).lower())[:140] for reason in reasons[:5]]
    return hashlib.sha256(json.dumps(sorted(canonical)).encode()).hexdigest()[:24]


def escalate_if_due(fp):
    try:hours=int(STORE.get_kv('escalation_after_hours','0') or 0)
    except ValueError:hours=0
    if hours not in (1,3,8):return 'already_active'
    now=STORE.now()
    quiet=STORE.get_kv('quiet_until','')
    try:
        if quiet and dt.datetime.fromisoformat(quiet)>now:return 'quiet'
    except ValueError:pass
    with STORE.db() as c:
        row=c.execute('''SELECT id,notified_at,ack_at,escalated_at FROM incidents
                         WHERE fingerprint=? ORDER BY created_at DESC LIMIT 1''',(fp,)).fetchone()
    if not row or not row[1] or row[2] or row[3]:return 'already_active'
    try:due=dt.datetime.fromisoformat(row[1])+dt.timedelta(hours=hours)
    except ValueError:return 'already_active'
    if now<due:return 'already_active'
    cfg=config()
    sent,failed=deliver({'title':'NetSec: red incident still needs review',
      'body':'An evidence-calibrated incident remains unacknowledged. Sign in to review.',
      'url':cfg['origin'].rstrip('/')+'/#jimmy','tag':'netsec-escalate-'+row[0]})
    if sent:
        with STORE.db() as c:c.execute('UPDATE incidents SET escalated_at=? WHERE id=?',(STORE.stamp(),row[0]))
    return 'escalated:'+str(sent)+'/failed:'+str(failed)


def poll():
    if not config():return 'disabled'
    try:
        if REPORT.stat().st_size>300000:return 'oversized_report'
        report=json.loads(REPORT.read_text())
        when=dt.datetime.fromisoformat(str(report['updated_at']).replace('Z','+00:00'))
        if when.tzinfo is None or abs((STORE.now()-when).total_seconds())>1800:return 'stale'
    except (OSError,KeyError,TypeError,ValueError):return 'no_report'
    fp=event_fingerprint(report)
    if fp is None:
        STORE.put_kv('incident_active','')
        return 'not_red'
    active=STORE.get_kv('incident_active','')
    if active==fp:return escalate_if_due(fp)
    rid=STORE.save_report(report)
    # A recurring identical red pattern inside a 6-hour window is not a new push.
    latest=STORE.now()
    with STORE.db() as c:
        previous=c.execute('SELECT created_at FROM incidents WHERE fingerprint=? ORDER BY created_at DESC LIMIT 1',(fp,)).fetchone()
    quiet_duplicate=False
    if previous:
        try:quiet_duplicate=latest-dt.datetime.fromisoformat(previous[0])<dt.timedelta(hours=6)
        except ValueError:pass
    incident_id=hashlib.sha256((fp+rid).encode()).hexdigest()[:24]
    with STORE.db() as c:
        c.execute('INSERT OR IGNORE INTO incidents(id,fingerprint,report_id,created_at) VALUES (?,?,?,?)',
                  (incident_id,fp,rid,latest.isoformat()))
        c.execute('INSERT OR REPLACE INTO kv VALUES (?,?)',('incident_active',fp))
        c.execute('DELETE FROM incidents WHERE id NOT IN (SELECT id FROM incidents ORDER BY created_at DESC LIMIT 100)')
    until=STORE.get_kv('quiet_until','')
    try:quiet=bool(until and dt.datetime.fromisoformat(until)>latest)
    except ValueError:quiet=False
    if quiet or quiet_duplicate:return 'quiet_or_duplicate'
    # Only an ID in the link; no confidential telemetry in notification bodies.
    cfg=config()
    safe_url=cfg['origin'].rstrip('/')+'/#jimmy&report='+rid
    sent,failed=deliver({'title':'NetSec: verified red incident',
                  'body':'New evidence-calibrated security finding. Sign in to review.',
                  'url':safe_url,'tag':'netsec-red-'+incident_id})
    with STORE.db() as c:
        c.execute('UPDATE incidents SET notified_at=?,last_error=? WHERE id=?',
                  (STORE.stamp() if sent else None, 'delivery_failed' if failed else None,incident_id))
    return 'sent:'+str(sent)+'/failed:'+str(failed)


def api(handler,path,data,send):
    cfg=config()
    if not cfg:return send(handler,503,{'ok':False,'error':'Web Push not configured on server'})
    if path=='/api/push/subscribe':
        item=data.get('subscription')
        if not isinstance(item,dict) or not allowed_endpoint(item.get('endpoint','')):
            raise ValueError('Unsupported browser push service')
        sub_id=STORE.add_subscription(item)
        return send(handler,201,{'ok':True,'subscription_id':sub_id})
    if path=='/api/push/unsubscribe':
        STORE.delete_subscription(data.get('endpoint',''))
        return send(handler,200,{'ok':True})
    if path=='/api/push/test':
        # Explicit human click only, no model/tool invocation.
        sent,failed=deliver({'title':'NetSec test notification',
            'body':'Notifications are connected. Sign in to review details.',
            'url':cfg['origin'].rstrip('/')+'/#jimmy','tag':'netsec-push-test'})
        return send(handler,200,{'ok':sent>0,'delivered':sent,'failed':failed})
    return send(handler,404,{'ok':False,'error':'Unsupported push action'})


if __name__=='__main__':
    if len(sys.argv)==2 and sys.argv[1]=='--poll':
        print('NetSec push:',poll())
    elif len(sys.argv)==2 and sys.argv[1]=='--send-one':
        _send_one()
    else:
        raise SystemExit('Usage: netsec_push.py --poll|--send-one')
