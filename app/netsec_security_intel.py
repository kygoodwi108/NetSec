#!/usr/bin/env python3
"""Bounded, read-only security context: advisory applicability, geography and CrowdSec.

No network requests, credentials, shell commands or automatic enforcement.
The CVE catalogue is deliberately a dated advisory watchlist, NOT an automated
vulnerability scanner. Package backports cannot be determined from nginx -v.
"""
import datetime as dt
import json
import os
from pathlib import Path

UTC=dt.timezone.utc
INVENTORY=Path(os.environ.get('NETSEC_SOFTWARE_INVENTORY','/etc/netsec-software-inventory.json'))
ADVISORIES=(
 {'id':'CVE-2026-123007','component':'nginx','feature':'http2','published':'2026-11-18',
  'source':'https://nginx.org/en/security_advisories.html','impact':'HTTP/2 memory corruption'},
 {'id':'CVE-2026-123633','component':'nginx','feature':'http2','published':'2026-11-18',
  'source':'https://nginx.org/en/security_advisories.html','impact':'HTTP/2 use-after-free'},
 {'id':'CVE-2026-123634','component':'nginx','feature':'resolver','published':'2026-11-18',
  'source':'https://nginx.org/en/security_advisories.html','impact':'Resolver use-after-free'},
 {'id':'CVE-2026-121810','component':'nginx','feature':'http3','published':'2026-11-18',
  'source':'https://nginx.org/en/security_advisories.html','impact':'HTTP/3 use-after-free'},
 {'id':'CVE-2026-113425','component':'nginx','feature':'mail','published':'2026-11-18',
  'source':'https://nginx.org/en/security_advisories.html','impact':'Mail proxy security issue'},
)

def inventory():
    try:
        if INVENTORY.stat().st_size>16000:return {'state':'invalid','reason':'oversized'}
        data=json.loads(INVENTORY.read_text(encoding='utf8'))
        if not isinstance(data,dict) or data.get('schema_version')!=1:
            return {'state':'invalid','reason':'schema'}
        components=data.get('components')
        if not isinstance(components,list):return {'state':'invalid','reason':'components'}
        safe=[]
        for x in components[:24]:
            if not isinstance(x,dict):continue
            name=str(x.get('name','')).lower()
            if name not in ('nginx','crowdsec','proxmox','debian','patchmon'):continue
            status=str(x.get('vendor_patch_status','unknown'))
            if status not in ('unknown','confirmed_patched','needs_vendor_review'):status='unknown'
            features={k:x.get('features',{}).get(k) for k in ('http2','http3','resolver','mail')
                      if isinstance(x.get('features'),dict) and x.get('features',{}).get(k) in (True,False)}
            safe.append({'name':name,'version':str(x.get('version',''))[:60],
                         'package_revision':str(x.get('package_revision',''))[:80],
                         'vendor_patch_status':status,'features':features,
                         'source':'operator inventory; not independently verified'})
        return {'state':'operator_supplied','components':safe,'warning':'Package and patch claims require vendor/distro verification'}
    except FileNotFoundError:return {'state':'not_configured','components':[]}
    except (OSError,ValueError,TypeError):return {'state':'invalid','components':[]}

def advisory_watch(inv):
    components=[x for x in inv.get('components',[]) if x.get('name')=='nginx']
    if not components:
        return {'state':'inventory_needed','items':[],'catalogue_updated':'2026-11-21',
                'limitation':'Nginx advisories exist, but the installed package revision and feature configuration have not been established'}
    comp=components[0];out=[]
    for cve in ADVISORIES:
        enabled=comp.get('features',{}).get(cve['feature'])
        # No upstream version-only vulnerability claims. Backported fixes are common.
        if enabled is False:state='feature_disabled'
        elif comp.get('vendor_patch_status')=='confirmed_patched':state='operator_reported_patched'
        else:state='needs_vendor_verification'
        out.append({'id':cve['id'],'state':state,'feature':cve['feature'],
                    'feature_enabled':enabled,'source':cve['source'],
                    'impact':cve['impact']})
    return {'state':'review' if any(x['state']=='needs_vendor_verification' for x in out) else 'operator_assessed',
            'catalogue_updated':'2026-11-21','items':out,
            'limitation':'Dated watchlist only; verify Debian/NGINX patch status and feature applicability with vendor advisories'}

def geography(countries):
    # This is Nginx ingress geography, not proof of authenticated access.
    foreign=0;canadian=0;unknown=0;seen=[]
    for item in countries[:20] if isinstance(countries,list) else []:
        if not isinstance(item,dict):continue
        country=str(item.get('country','')).strip()
        try:count=max(0,int(item.get('requests') or 0))
        except (TypeError,ValueError):continue
        if country.lower() in ('canada','ca'):canadian+=count
        elif country.lower() in ('unknown','n/a','', 'unresolved'):unknown+=count
        else:
            foreign+=count
            seen.append({'country':country[:60],'requests':count})
    return {'policy':'authorized human access normally originates in Canada',
            'foreign_requests_sample':foreign,'canadian_requests_sample':canadian,
            'unknown_geo_requests_sample':unknown,'foreign_countries':seen[:8],
            'state':'foreign_inbound_observed' if foreign else 'no_foreign_requests_in_sample',
            'limitation':'Nginx HTTP request geography only: cannot distinguish Transmission peer flows, identity, service, or login success; country alone never causes a ban'}

def enforcement(export,now=None):
    now=now or dt.datetime.now(UTC)
    obj=export if isinstance(export,dict) else {}
    state=str(obj.get('state') or 'unavailable')
    bouncers=obj.get('bouncers')
    if not isinstance(bouncers,list):bouncers=[]
    most_recent=None
    for b in bouncers[:30]:
        if not isinstance(b,dict) or not b.get('valid'):continue
        value=b.get('last_pull')
        if not isinstance(value,str):continue
        try:
            at=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
            if at.tzinfo is None:continue
            at=at.astimezone(UTC)
            if at<=now+dt.timedelta(minutes=5) and (most_recent is None or at>most_recent):most_recent=at
        except ValueError:continue
    age=int((now-most_recent).total_seconds()) if most_recent else None
    if age is not None and age<0:age=0
    current=state=='active' and age is not None and age<=300
    return {'state':'recent_lapi_pull' if current else 'unverified_or_stale',
            'export_state':state,'last_valid_pull_at':most_recent.isoformat() if most_recent else None,
            'last_valid_pull_age_seconds':age,'registered_bouncers':len(bouncers),
            'enforcement_proven':False,
            'limitation':'Recent LAPI pulls are evidence of synchronization, not proof that the Nginx bouncer denied a controlled request'}

def snapshot(countries,enforcement_export):
    inv=inventory()
    return {'inventory':inv,'advisories':advisory_watch(inv),'geography':geography(countries),
            'bouncer':enforcement(enforcement_export),'policy_mode':'monitor_only',
            'generated_at':dt.datetime.now(UTC).isoformat()}
