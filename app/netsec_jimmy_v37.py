#!/usr/bin/env python3
"""Evidence-first Jimmy v3.7. Deterministic read-only correlation and advice guardrails.

This module NEVER executes commands, performs network requests, changes bans, or alters services.
It accepts previously collected status and verification data; no secrets or raw log bodies.
"""
import datetime as dt
import ipaddress
import json
import re

UTC = dt.timezone.utc
PROMPT_GUIDANCE = (
    ' EVIDENCE PRIORITY: verified observations in evidence_brief and verification_results outrank '
    'generic speculation. A recorded Nginx CrowdSec denial confirms *observed bouncer enforcement*, '
    'not a newly performed HTTP 403 test. Never repeat a generic verification recommendation if '
    'that condition has already been checked. Separate CrowdSec ngx.timer API connectivity errors '
    'from application upstream errors. A scan of /.env is not a disclosure, and an HTTP 200 from '
    'a login page or frontend asset is not an authenticated intrusion. Tests not yet run are NOT '
    'verified. For sensitive-path checks, follow the reported verified test results and the operator-selected '
    'probe mode. Authorized full-scan mode may check every configured path at once; do not assume it ran unless reported. Quote dates/ages where useful. '
    'If no unresolved issue requires action, return an empty recommended_actions array. '
    'No arbitrary commands, new bans, firewall edits, or dangerous changes.'
)


def _check(v, name):
    return next((x for x in v.get('checks', []) if isinstance(x, dict) and x.get('id') == name), {})


def _public(address):
    try:
        return ipaddress.ip_address(str(address)).is_global
    except (ValueError, TypeError):
        return False


def _clip(s, n=190):
    return str(s or '')[:n]


def _stamp(timestamp):
    if isinstance(timestamp, (int, float)):
        return dt.datetime.fromtimestamp(timestamp, UTC).isoformat()
    return _clip(timestamp, 55) if isinstance(timestamp, str) else None


def build_review(verification, status=None):
    """A small authoritative evidence summary. `verified` means *specified* check, not compromise cleared."""
    v = verification if isinstance(verification, dict) else {}
    status = status if isinstance(status, dict) else {}
    generated = v.get('generated_at')
    checks = []
    for item in (v.get('checks') or [])[:8]:
        if not isinstance(item, dict):
            continue
        checks.append({
            'id': _clip(item.get('id'), 55),
            'state': _clip(item.get('state', 'unavailable'), 28),
            'observed_at': _stamp(generated),
            'result': _clip(item.get('result'), 390),
            'limits': _clip(item.get('limits'), 430),
            'provenance': 'Automated read-only diagnostic',
        })

    errors = v.get('nginx_error_summary') or {}
    categories = errors.get('class_counts') or {}
    def count(key):
        try:
            return max(0, int(categories.get(key, 0) or 0))
        except (ValueError, TypeError):
            return 0
    upstream = {
        'real_upstream_errors_sample': sum(count(k) for k in (
            'upstream_connection_failure', 'upstream_timeout', 'upstream_closed', 'no_live_upstreams')),
        'crowdsec_timer_connectivity_sample': count('crowdsec_timer_connectivity'),
        'per_upstream': [{'address': _clip(x.get('address'), 80),
                          'errors': x.get('errors', 0)}
                         for x in (errors.get('upstreams') or [])[:6] if isinstance(x, dict)],
        'source': 'Bounded Nginx error-log scan; not all logs',
        'observed_at': _stamp(generated),
    }
    denials = [d for d in (errors.get('observed_bouncer_denials') or []) if isinstance(d, dict)]
    public_denials = [d for d in denials if _public(d.get('ip'))]
    internal = [d for d in denials if not _public(d.get('ip'))]
    crowdsec = _check(v, 'crowdsec_enforcement')
    observed = crowdsec.get('state') == 'verified' and bool(denials)
    evidence = {
        'state': 'observed_bouncer_denials' if observed else _clip(crowdsec.get('state','unavailable')),
        'public_denial_sources_sample': len(public_denials),
        'private_or_reserved_denial_sources_sample': len(internal),
        'observed_denial_events_sample': sum(int(d.get('blocked_requests_sample') or 0) for d in denials),
        'last_observed_denial_at': max((_stamp(d.get('last_seen')) for d in denials if d.get('last_seen')), default=None),
        'new_synthetic_403_test': False,
        'note': ('Observed Nginx bouncer denials and active pulling; no fresh synthetic 403 test.'
                 if observed else 'No verified bouncer denial in this sample; do not assert a live 403 test.'),
        'observed_at': _stamp(generated),
    }
    sensitive = _check(v, 'sensitive_paths')
    paths = []
    for p in (v.get('sensitive_path_details') or [])[:12]:
        if not isinstance(p,dict):continue
        paths.append({'host':_clip(p.get('host'),100),'path':_clip(p.get('path'),150),
                      'http_status':p.get('http_status'), 'outcome':_clip(p.get('outcome'),50),
                      'tested_at':_stamp(p.get('at_epoch'))})
    sensitive_summary = {'state':sensitive.get('state','unavailable'),
                         'result':_clip(sensitive.get('result'),390),
                         'last_results':paths,
                         'next_test': _clip(sensitive.get('limits'),260),
                         'note':'404/403 does not prove every path safe; 200 does not alone prove disclosure.'}
    # The 1.1.0 standalone deployment uses direct HTTP/TCP checks by default.
    # Unlike the old homepage-only assessment, these become valid evidence too.
    source=status.get('service_source')
    service=(status.get('homepage') or {}) if source=='homepage' else (status.get('service_monitor') or {})
    statuses=status.get('services') or []
    service_fresh=(service.get('state')=='fresh' if source=='homepage' else service.get('state')=='checked')
    try:
        checked=dt.datetime.fromisoformat(str(service.get('checked_at','')).replace('Z','+00:00'))
        if checked.tzinfo is None or abs((dt.datetime.now(dt.timezone.utc)-checked).total_seconds())>180:
            service_fresh=False
    except (ValueError,TypeError):service_fresh=False
    service_counts = {label:sum(x.get('status')==label for x in statuses if isinstance(x,dict))
                      for label in ('up','down','stale','unknown')}
    services = {'source':'Legacy read-only homepage feed' if source=='homepage' else 'NetSec HTTP/TCP direct reachability',
                'fresh':service_fresh,'state':service.get('state') if service else 'not_available',
                'checked_at':service.get('checked_at'),
                'counts':service_counts if service_fresh else {},
                'limitation':'HTTP/TCP reachability, not authenticated application or host integrity'}
    scheduled = []
    if sensitive.get('state') in ('partial', 'unavailable', 'not_configured'):
        scheduled.append({'id':'sensitive_paths', 'state':'scheduled' if sensitive.get('state')=='partial' else 'needs_configuration',
                          'description':('Some sensitive-path results remain unverified; approved full scan is enabled, review results or next scan.' if 'Authorized full-scan' in _clip(sensitive.get('limits'),500) else 'Other sensitive-path checks remain unverified; rotating verification is in effect or full mode is awaiting operator authorization.')})
    if service_fresh and service_counts['up']>0 and service_counts['down']==0 and 0<upstream['real_upstream_errors_sample']<=10:
        scheduled.append({'id':'backend_observation', 'state':'monitoring',
                          'description':'Only a few historical upstream errors appeared in the bounded sample; service HTTPS reachability currently responds. Monitor for recurrence.'})
    if internal:
        scheduled.append({'id':'internal_ban_history', 'state':'historical_review',
                          'description':'A private/reserved IP appears in past ban-denial events; not classified as an external attack.'})
    return {
        'generated_at':_stamp(generated),
        'checks':checks,
        'crowdsec':evidence,
        'nginx':upstream,
        'sensitive_paths':sensitive_summary,
        'service_health':services,
        'follow_up_states':scheduled,
        'scope':'Nginx HTTP telemetry, CrowdSec decisions/denials and bounded read-only checks only',
        'do_not_claim':'No direct knowledge of successful login, secret disclosure or host compromise',
    }


def model_brief(review):
    """Limit context size and keep essential evidence even during model retry."""
    result = {k:review.get(k) for k in ('generated_at','crowdsec','nginx','service_health',
                                      'follow_up_states','scope','do_not_claim')}
    sen = review.get('sensitive_paths') or {}
    result['sensitive_paths'] = {'state':sen.get('state'), 'result':sen.get('result'),
                                 'last_results':(sen.get('last_results') or [])[:3],
                                 'next_test':sen.get('next_test')}
    return result


def compact_verification(v):
    """Retry-friendly evidence: omit bulky denial logs but preserve each verified result."""
    if not isinstance(v, dict):return {}
    return {
        'generated_at':v.get('generated_at'),
        'checks': [{'id':x.get('id'), 'state':x.get('state'),
                    'result':_clip(x.get('result'), 260), 'limits':_clip(x.get('limits'), 170)}
                   for x in (v.get('checks') or [])[:5] if isinstance(x, dict)],
        'sensitive_path_details':[{'host':p.get('host'),'path':p.get('path'),
                                   'http_status':p.get('http_status'),'outcome':p.get('outcome'),
                                   'at_epoch':p.get('at_epoch')}
                                  for p in (v.get('sensitive_path_details') or [])[:8] if isinstance(p,dict)],
        'nginx_error_summary':{'class_counts':(v.get('nginx_error_summary') or {}).get('class_counts'),
                               'upstreams':(v.get('nginx_error_summary') or {}).get('upstreams',[])[:5],
                               'observed_denial_sources':len((v.get('nginx_error_summary') or {}).get('observed_bouncer_denials') or [])},
    }


def extract_json_object(content):
    """Tolerate fenced/wrapped valid JSON; never invent missing fields or repair truncated JSON."""
    if not isinstance(content, str):raise ValueError('Model output is not text')
    txt=content.strip()
    fenced=re.fullmatch(r'```(?:json)?\s*(.*?)\s*```',txt,flags=re.I|re.S)
    if fenced:txt=fenced.group(1).strip()
    try:
        obj=json.loads(txt)
        if not isinstance(obj,dict):raise ValueError('JSON top level is not an object')
        return txt
    except json.JSONDecodeError:
        pass
    decoder=json.JSONDecoder()
    for match in re.finditer(r'\{',txt[:200]):
        try:
            obj, end=decoder.raw_decode(txt[match.start():])
        except json.JSONDecodeError:
            continue
        if isinstance(obj,dict) and set(obj)&{'severity','summary','observations'}:
            # The complete JSON was present, with extraneous model preamble/trailer.
            return json.dumps(obj,separators=(',',':'),ensure_ascii=False)
    raise ValueError('AI did not return a complete JSON object')


def _redundant_action(action, review):
    a=action.lower()
    e=review.get('crowdsec') or {}
    if e.get('state')=='observed_bouncer_denials' and (
       re.search(r'(verify|confirm|test|check|correlate|inspect|review|ensure)',a) and
       re.search(r'(crowdsec|bouncer|enforcement|http\s*403|ban\b|banned\b|decision timestamps|\.env from a local machine)',a)):
        return True
    # The read-only homepage monitor has already checked public service reachability.
    # Do not recommend generic restart/error-log work for a handful of historical failures
    # when the feed is currently fresh and all listed services respond. This is not proof
    # that every application function works, so preserve specific, non-generic diagnosis.
    health=review.get('service_health') or {}
    counts=health.get('counts') or {}
    nginx=review.get('nginx') or {}
    if health.get('fresh') and counts.get('up',0)>0 and counts.get('down',0)==0 and (
       nginx.get('real_upstream_errors_sample',1000)<=10) and (
       re.search(r'(review|check|inspect|verify) upstream health',a) or
       re.search(r'(check|inspect|review) container logs for (connection timeouts|service restarts)',a)):
        return True
    # We have already classified Nginx error.log, though actual backend health may still need attention.
    if re.search(r'(review|inspect|check|categorize|classify|distinguish)',a) and (
       'nginx error.log' in a or 'nginx error log' in a) and re.search(r'(upstream|connection)',a):
        return True
    if re.search(r'(send|simulate|synthetic|probe|batch|run|request)',a) and (
       re.search(r'\.(env|git)',a) or 'sensitive path' in a) and (
       review.get('sensitive_paths') or {}).get('state')=='partial':
        return True
    return False


def reconcile(advice, verification, status):
    """Treat model text as advisory; suppress contradictory/repeated checks after generation."""
    if not isinstance(advice,dict):raise ValueError('Invalid AI analysis')
    review=build_review(verification,status)
    recommended=[]; suppressed=[]
    for item in (advice.get('recommended_actions') or []):
        if not isinstance(item,str):continue
        item=item.strip()
        if not item:continue
        if _redundant_action(item,review):suppressed.append(item);continue
        if item not in recommended:recommended.append(item[:300])
    # Avoid generic worklists when tests already ran; an empty list means there is no new manual action.
    advice['recommended_actions']=recommended[:3]
    observations=[]
    for item in (advice.get('observations') or []):
        if not isinstance(item,str):continue
        low=item.lower()
        if review['crowdsec']['state']=='observed_bouncer_denials' and (
            ('not verified' in low or 'requires verification' in low) and
            ('ban' in low or 'crowdsec' in low or 'enforcement' in low)):
            continue
        if (review['nginx']['crowdsec_timer_connectivity_sample'] > review['nginx']['real_upstream_errors_sample'] * 5
            and ('hundreds of upstream failures' in low or 'hundreds of backend failures' in low)):
            continue
        observations.append(item[:260])
    advice['observations']=observations[:4]
    advice['suppressed_duplicate_actions']=len(suppressed)
    advice['evidence_review']=review
    return advice
