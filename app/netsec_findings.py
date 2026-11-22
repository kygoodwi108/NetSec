#!/usr/bin/env python3
"""Evidence-derived dynamic NetSec findings, not model-invented security claims."""
import math

def _n(value):
    try:return max(0,int(value))
    except (ValueError,TypeError):return 0

def build(evidence,history,telemetry=None):
    e=evidence if isinstance(evidence,dict) else {}
    history=history if isinstance(history,dict) else {}
    telemetry=telemetry if isinstance(telemetry,dict) else {}
    findings=[]
    def add(key,title,priority,summary,confidence='medium',category='infrastructure',lifecycle='active'):
        findings.append({'id':key,'title':title,'priority':priority,'summary':summary,
                         'confidence':confidence,'category':category,'lifecycle':lifecycle,
                         'origin':'bounded verified telemetry'})
    svc=e.get('service_health') or {}
    down=_n(svc.get('down')) if svc.get('fresh') else 0
    historical_backend=_n(e.get('sampled_backend_errors'))
    historical_timer=_n(e.get('sampled_crowdsec_timer_errors'))
    backend=_n(e.get('recent_backend_errors',historical_backend))
    timer=_n(e.get('recent_crowdsec_timer_errors',historical_timer))
    requests=_n(e.get('requests_aggregate'))
    errors=_n(e.get('http_5xx_aggregate'))
    paths=e.get('sensitive_paths') or {}
    review=_n(paths.get('requires_review'))
    if down:
        add('services-down','Unreachable configured services','high' if down>=2 else 'medium',
            str(down)+' configured service(s) failed a fresh reachability check; identify affected services before attributing root cause.')
    if backend:
        add('nginx-upstream','Upstream failures in Nginx logs','high' if backend>=20 else 'medium',
            str(backend)+' classified upstream error(s) in a bounded sample. Correlate service, backend and timestamps. This alone does not prove hostile activity.')
    if historical_backend and not backend:
        add('nginx-upstream-resolved','Historical upstream failures — no recent recurrence','low',
            str(historical_backend)+' upstream error(s) remain in the 24h sample; no matching errors in the most recent 15 minutes. Verify backend health before closing.',
            'medium','availability','recovered')
    if historical_timer and not timer:
        add('crowdsec-connectivity-recovered','Historical CrowdSec connectivity warnings','low',
            str(historical_timer)+' timer/LAPI error(s) remain in the 24h sample; none in the last 15 minutes. Current enforcement must still be verified.',
            'medium','enforcement','recovered')
    if timer>=3:
        add('crowdsec-connectivity','CrowdSec connectivity warnings','medium',
            str(timer)+' CrowdSec timer/LAPI error(s) observed in bounded diagnostics. Verify relay health and bouncer synchronization.')
    if review:
        add('sensitive-path','Sensitive endpoint responses require review','high',
            str(review)+' sensitive-path check(s) need human inspection; an HTTP status alone does not establish disclosure.')
    if errors>=20 and requests>=50 and errors/requests>=0.05:
        add('http-error-rate','Elevated HTTP 5xx responses','medium',
            str(errors)+' HTTP 5xx responses across '+str(requests)+' observed requests (rolling 24h). Attribute to specific services before assuming an incident.',
            'low' if not backend else 'medium','availability')
    intelligence=telemetry.get('security_intelligence') or {}
    advisory=intelligence.get('advisories') or {}
    review_cves=[x.get('id','') for x in (advisory.get('items') or [])
                 if isinstance(x,dict) and x.get('state')=='needs_vendor_verification']
    if advisory.get('state')=='inventory_needed':
        add('cve-inventory-needed','Security advisory applicability not verified','medium',
            'NGINX package revision and enabled features have not been inventoried; current November 2026 advisories cannot be evaluated on this host.',
            'high','visibility','unverified')
    if review_cves:
        add('cve-package-review','Verify NGINX security advisory applicability','medium',
            ', '.join(review_cves[:5])+': review vendor package revision and enabled modules; this is NOT a confirmed vulnerability.',
            'high','vulnerability','unverified')
    geo=intelligence.get('geography') or {}
    if _n(geo.get('foreign_requests_sample')):
        add('international-traffic','Non-Canadian Nginx requests observed','low',
            str(_n(geo.get('foreign_requests_sample')))+' foreign-origin request(s) in sampled Nginx traffic. Country alone does not prove unauthorized access; attribute to virtual host and authentication before escalating.',
            'medium','traffic')
    bouncer=intelligence.get('bouncer') or {}
    if _n(bouncer.get('registered_bouncers')) and bouncer.get('state')!='recent_lapi_pull':
        add('bouncer-sync','CrowdSec bouncer synchronization unverified','medium',
            'A registered bouncer has no fresh, parseable LAPI pull in the current export. Check collector freshness, local API connectivity and real enforcement separately.',
            'medium','enforcement','unverified')
    probes=_n(telemetry.get('probes_24h'))
    if probes>=50 and requests>=100 and probes/requests>=0.01:
        add('probe-activity','Elevated probe-like HTTP requests','medium',
            str(probes)+' of '+str(requests)+' observed 24h requests matched known probe-like paths. Distinguish routine internet scanning from a targeted attempt; HTTP response codes alone do not prove exploitation.',
            'low','traffic')
    denied=_n(telemetry.get('http_401_24h'))+_n(telemetry.get('http_403_24h'))
    if denied>=100 and requests>=100 and denied/requests>=0.5:
        add('auth-denials','High share of 401/403 responses','medium',
            str(denied)+' of '+str(requests)+' observed responses were 401/403. Identify affected endpoints and callers before interpreting this as an attack.',
            'low','traffic')
    if _n(telemetry.get('log_files_readable'))==0 and telemetry:
        add('missing-logs','Security log visibility unavailable','high',
            'No readable Nginx access logs are reported. Investigation and threat classification are incomplete.',
            'high','visibility')
    if (telemetry.get('crowdsec') or {}).get('export_error'):
        add('crowdsec-export','CrowdSec alert evidence unavailable','medium',
            'The CrowdSec alert export could not be read. Confirm collection and refresh status before interpreting missing events.',
            'high','visibility')
    previous=(history.get('previous_assessments') or []) if isinstance(history.get('previous_assessments'),list) else []
    prior=next((p for p in previous if isinstance(p,dict) and p.get('rolling_24h_requests') is not None),None)
    if prior:
        old=_n(prior.get('rolling_24h_requests'))
        if old>=100 and requests>=100 and (requests>=old*1.8 or requests<=old*0.3):
            direction='higher' if requests>old else 'lower'
            add('traffic-change','Material change in rolling traffic','medium',
                'Current 24h request count ('+str(requests)+') is '+direction+' than a previous overlapping rolling-24h snapshot ('+str(old)+'). Check whether this reflects normal scheduled traffic.',
                'low','traffic')
    return findings[:8]
