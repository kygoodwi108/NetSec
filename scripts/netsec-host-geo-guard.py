#!/usr/bin/env python3
"""Opt-in Proxmox-host GeoIP2 ingress policy. NEVER run from NetSec LXC.

prepare: install Debian GeoIP2 dependencies and refresh validated DB-IP MMDB.
refresh-db: update MMDB without apt operations or changing any policy.
enable: install on a clean Nginx host with 5-minute rollback.
set-countries: safely update an ACTIVE legacy/new guard (including CA+US migration)
               with an independent five-minute policy rollback.
confirm: cancel an active guard/policy rollback timer after real access testing.
rollback: restore the previous entire Nginx setup, or a pending policy change.
status: read-only report. Does not inspect router/host firewall exposure.

No firewall rules, IP-based bans, X-Forwarded-For trust, VPN or torrent routing.
"""
import argparse
import datetime as dt
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request

ROOT=Path(os.environ.get('NETSEC_HOST_GEO_ROOT','/root/netsec-canada-nginx'))
CONF=Path(os.environ.get('NETSEC_HOST_GEO_CONF','/etc/nginx/conf.d/90-netsec-canada-geo.conf'))
DB=Path(os.environ.get('NETSEC_HOST_GEO_DB','/var/lib/netsec-geoip/dbip-country-lite.mmdb'))
NGINX_ENABLED=Path(os.environ.get('NETSEC_HOST_GEO_SITES','/etc/nginx/sites-enabled'))
FULL_TIMER='netsec-canada-rollback.timer'  # compatibility with the 2026 legacy guard
POLICY_TIMER='netsec-geo-policy-rollback.timer'
MARKER='NETSEC_CANADA_HTTPS_GATE'
SNIP='    if ($netsec_ca_denied) { return 403; } # '+MARKER+'\n'
COUNTRY_PATTERN=re.compile(r'^[A-Z]{2}$')
MAP_PATTERN=re.compile(r'(?ms)^map\s+"\$netsec_local_client:\$netsec_country_code"\s+\$netsec_ca_denied\s*\{.*?^\}')
ALLOW_LINE=re.compile(r'(?m)^\s*"0:([A-Z]{2})"\s+0;\s*$')


def call(*args, check=True, capture=False):
    return subprocess.run(args,check=check,text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture else None)

def host_only():
    if os.geteuid()!=0 or not Path('/etc/pve').is_dir():
        raise SystemExit('This command requires root on the Proxmox HOST, not LXC 108')

def countries(value):
    parsed=tuple(dict.fromkeys(x.strip().upper() for x in value.split(',')))
    if not parsed or len(parsed)>20 or any(not COUNTRY_PATTERN.fullmatch(x) for x in parsed):
        raise ValueError('Provide comma-separated ISO 3166-1 alpha-2 codes, e.g. CA,US')
    return parsed

def map_text(allowed):
    rules='\n'.join('    "0:'+c+'" 0;' for c in allowed)
    return ('map "$netsec_local_client:$netsec_country_code" $netsec_ca_denied {\n'
            '    default 1;\n'+rules+'\n    ~^1: 0;\n}')

def geo_config(allowed):
    return ('''# NetSec host HTTPS GeoIP policy — DB-IP Lite, CC BY 4.0
# https://db-ip.com/db/lite.php
# Only the actual TCP peer IP is used; client-controlled forwarding headers ignored.
geoip2 /var/lib/netsec-geoip/dbip-country-lite.mmdb {
    auto_reload 60m;
    $netsec_country_code default=ZZ source=$remote_addr country iso_code;
}
geo $netsec_local_client {
    default 0;
    127.0.0.0/8 1;
    10.0.0.0/8 1;
    172.16.0.0/12 1;
    192.168.0.0/16 1;
    ::1/128 1;
    fc00::/7 1;
    fe80::/10 1;
}
'''+map_text(allowed)+'\n')

def replace_map(original,allowed):
    matches=list(MAP_PATTERN.finditer(original))
    if len(matches)!=1:
        raise ValueError('Expected exactly one known NetSec geo map. Refusing unfamiliar configuration.')
    existing=matches[0].group()
    if 'default 1;' not in existing or '~^1: 0;' not in existing:
        raise ValueError('Unknown NetSec geo map layout; refusing rewrite')
    return original[:matches[0].start()]+map_text(allowed)+original[matches[0].end():]

def current_countries():
    if not CONF.exists():return ()
    matches=MAP_PATTERN.findall(CONF.read_text())
    if len(matches)!=1:raise ValueError('Unrecognized current GeoIP policy')
    return tuple(ALLOW_LINE.findall(matches[0]))

def module_ready():
    return any(Path('/etc/nginx/modules-enabled').glob('*geoip2*'))

def refresh_db():
    host_only()
    if not shutil.which('mmdblookup'):raise SystemExit('mmdblookup missing: run prepare')
    month=dt.datetime.now(dt.timezone.utc).strftime('%Y-%m')
    url='https://download.db-ip.com/free/dbip-country-lite-'+month+'.mmdb.gz'
    DB.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(dir=DB.parent,prefix='.geoip-') as tmp:
        compressed=Path(tmp)/'country.mmdb.gz'
        request=urllib.request.Request(url,headers={'User-Agent':'NetSecHostGeo/1.4'})
        with urllib.request.urlopen(request,timeout=60) as response,compressed.open('wb') as dest:
            total=0
            while True:
                chunk=response.read(262144)
                if not chunk:break
                total+=len(chunk)
                if total>25_000_000:raise ValueError('Unusually large compressed GeoIP database')
                dest.write(chunk)
        candidate=Path(tmp)/'country.mmdb'
        with gzip.open(compressed,'rb') as source,candidate.open('wb') as dest:
            total=0
            while True:
                chunk=source.read(262144)
                if not chunk:break
                total+=len(chunk)
                if total>40_000_000:raise ValueError('Unusually large GeoIP database')
                dest.write(chunk)
        if candidate.stat().st_size<1_000_000:raise ValueError('Incomplete GeoIP database')
        for ip,code in (('8.8.8.8','US'),('24.114.0.1','CA')):
            output=call('mmdblookup','-f',str(candidate),'-i',ip,
                        'country','iso_code',capture=True).stdout
            if '"'+code+'"' not in output:raise ValueError('GeoIP validation failed for '+ip)
        candidate.chmod(0o644)
        os.replace(candidate,DB)
    print('Validated GeoIP database updated:',DB,'(DB-IP Country Lite CC BY 4.0)')
    print('Existing Nginx GeoIP2 auto_reload handles database refresh; no reload was requested')

def prepare():
    host_only()
    call('apt-get','update')
    # Correct Debian 13/Trixie package; old manual script used libmaxminddb-bin.
    call('apt-get','install','-y','libnginx-mod-http-geoip2','mmdb-bin')
    if not module_ready():raise SystemExit('GeoIP2 Nginx module missing after installation')
    refresh_db()
    print('Prepared. No policy enabled or modified.')

def strip_comments_and_strings(content):
    result=list(content);quote=None;escape=False;comment=False
    for i,char in enumerate(content):
        if comment:
            if char=='\n':comment=False
            else:result[i]=' '
            continue
        if quote:
            result[i]=' '
            if escape:escape=False
            elif char=='\\':escape=True
            elif char==quote:quote=None
            continue
        if char=='#':result[i]=' ';comment=True
        elif char in '"\x27':result[i]=' ';quote=char
    return ''.join(result)

def transform(original):
    clean=strip_comments_and_strings(original)
    offsets=[]
    for match in re.finditer(r'\bserver\s*\{',clean):
        opened=clean.find('{',match.start(),match.end())
        depth=0;end=None
        for pos in range(opened,len(clean)):
            if clean[pos]=='{':depth+=1
            elif clean[pos]=='}':
                depth-=1
                if depth==0:end=pos;break
        if end is None:raise ValueError('Unbalanced Nginx server block')
        body=clean[opened+1:end]
        if not re.search(r'\blisten\s+[^;]*\b443\b[^;]*;',body):continue
        if MARKER in original[opened+1:end]:continue
        offsets.append(opened+1)
    for pos in reversed(offsets):original=original[:pos]+'\n'+SNIP+original[pos:]
    return original,len(offsets)

def sites():
    seen=[]
    for item in sorted(NGINX_ENABLED.iterdir()):
        if not item.is_file():continue
        path=item.resolve()
        if path not in seen:seen.append(path)
    return seen

def state_dir():
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    os.chmod(ROOT,0o700)

def rotate_old_backup():
    old=ROOT/'backup'
    if old.exists():
        # A previous rollback can leave /backup behind; never overwrite or delete it.
        archive=ROOT/('backup-previous-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+str(os.getpid()))
        old.rename(archive)
        print('Preserved earlier backup:',archive)

def timer_active(name):
    return call('systemctl','is-active','--quiet',name,check=False).returncode==0

def schedule_timer(unit,command):
    # Persistent script path is required because GitHub checkout/temp paths can disappear.
    script=ROOT/'rollback.py'
    shutil.copy2(Path(__file__),script)
    call('systemd-run','--unit='+unit,'--on-active=5min','/usr/bin/python3',str(script),command)

def enable(allowed):
    host_only()
    if not module_ready() or not DB.exists():raise SystemExit('Run prepare first')
    if CONF.exists() or (ROOT/'active.json').exists():
        raise SystemExit('Existing policy detected. Use set-countries; do NOT enable twice.')
    if timer_active(FULL_TIMER) or timer_active(POLICY_TIMER):
        raise SystemExit('A previous rollback timer is active')
    call('nginx','-t')
    changes=[]
    for path in sites():
        original=path.read_text()
        new,n=transform(original)
        if n:changes.append((path,new,n))
    if not changes:raise SystemExit('No unprotected HTTPS blocks found; refusing to install')
    state_dir();rotate_old_backup()
    backup=ROOT/'backup';backup.mkdir(mode=0o700)
    manifest=[]
    for i,(path,_,count) in enumerate(changes):
        backup_file=backup/('file-'+str(i))
        shutil.copy2(path,backup_file)
        manifest.append({'path':str(path),'backup':str(backup_file)})
    (ROOT/'active.json').write_text(json.dumps({'files':manifest,'geo_conf':str(CONF)},indent=2))
    os.chmod(ROOT/'active.json',0o600)
    try:
        CONF.write_text(geo_config(allowed))
        for path,new,_ in changes:path.write_text(new)
        call('nginx','-t')
        schedule_timer('netsec-canada-rollback','rollback')
        call('systemctl','reload','nginx')
    except Exception:
        rollback(cancel=False)
        raise
    print('Enabled for',','.join(allowed),'across',sum(c for _,_,c in changes),
          'HTTPS blocks; five-minute automatic rollback scheduled.')

def set_countries(allowed):
    host_only()
    if not CONF.exists() or not (ROOT/'active.json').exists():
        raise SystemExit('No managed policy found. Use enable or inspect configuration manually.')
    if (ROOT/'policy-pending.json').exists():
        raise SystemExit('Country policy update already pending; confirm or rollback-policy first')
    if timer_active(FULL_TIMER) or timer_active(POLICY_TIMER):
        raise SystemExit('An earlier rollback timer is active; confirm it before updating')
    previous=CONF.read_text()
    updated=replace_map(previous,allowed)
    if previous==updated:
        print('Policy already allows:',','.join(allowed));return
    state_dir()
    backup=ROOT/('policy-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+str(os.getpid())+'.conf')
    shutil.copy2(CONF,backup)
    manifest=ROOT/'policy-pending.json'
    manifest.write_text(json.dumps({'backup':str(backup),'policy_file':str(CONF)}))
    os.chmod(manifest,0o600)
    try:
        CONF.write_text(updated)
        call('nginx','-t')
        schedule_timer('netsec-geo-policy-rollback','rollback-policy')
        call('systemctl','reload','nginx')
    except Exception:
        rollback_policy(cancel=False)
        raise
    print('New allowed countries:',','.join(allowed))
    print('Five-minute rollback scheduled. Test Canada and US from real connections.')
    print('Run confirm after verifying access, or rollback-policy to restore prior countries.')

def rollback_policy(cancel=True):
    host_only()
    manifest=ROOT/'policy-pending.json'
    if not manifest.exists():
        print('No pending country policy to revert');return
    obj=json.loads(manifest.read_text())
    source=Path(obj['backup'])
    target=Path(obj['policy_file'])
    if target!=CONF or not source.is_file():raise SystemExit('Policy rollback backup invalid')
    shutil.copy2(source,target)
    call('nginx','-t')
    call('systemctl','reload','nginx')
    manifest.unlink()
    if cancel:call('systemctl','stop',POLICY_TIMER,check=False)
    print('Previous country policy restored')

def rollback(cancel=True):
    host_only()
    if (ROOT/'policy-pending.json').exists():
        rollback_policy(cancel=cancel)
    manifest=ROOT/'active.json'
    if not manifest.exists():print('No managed HTTPS GeoIP deployment');return
    data=json.loads(manifest.read_text())
    for item in data['files']:
        shutil.copy2(item['backup'],item['path'])
    Path(data['geo_conf']).unlink(missing_ok=True)
    call('nginx','-t')
    call('systemctl','reload','nginx')
    manifest.unlink()
    if cancel:call('systemctl','stop',FULL_TIMER,check=False)
    print('Original HTTPS configuration restored')

def confirm():
    host_only()
    policy=ROOT/'policy-pending.json'
    if policy.exists():
        # Callers must verify real Canadian and US access before confirmation.
        call('nginx','-t')
        call('systemctl','stop',POLICY_TIMER)
        policy.unlink()
        print('Country policy confirmed; timer cancelled, backup retained')
        return
    if not (ROOT/'active.json').exists():raise SystemExit('No managed policy found')
    call('nginx','-t')
    if timer_active(FULL_TIMER):call('systemctl','stop',FULL_TIMER)
    print('HTTPS geo restrictions confirmed. No outstanding rollback timer.')

def status():
    host_only()
    print('Managed deployment:',(ROOT/'active.json').exists())
    print('Geo configuration:',CONF,'exists:',CONF.exists())
    if CONF.exists():
        try:print('Allowed countries:',','.join(current_countries()))
        except ValueError as exc:print('Policy inspection failed:',exc)
    print('Pending country change:',(ROOT/'policy-pending.json').exists())
    print('Rollback timer active:',timer_active(FULL_TIMER) or timer_active(POLICY_TIMER))
    print('GeoIP database:',DB,'exists:',DB.exists())
    print('Nginx service active:',call('systemctl','is-active','--quiet','nginx',check=False).returncode==0)
    print('Direct SSH/Proxmox/SPICE ports and router forwards are not covered.')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('prepare','refresh-db','enable','set-countries',
                                            'confirm','rollback','rollback-policy','status'))
    parser.add_argument('--countries',default='CA,US',help='Comma-separated ISO-2 codes (default CA,US)')
    args=parser.parse_args()
    allowed=countries(args.countries)
    actions={'prepare':lambda:prepare(),'refresh-db':lambda:refresh_db(),
             'enable':lambda:enable(allowed),'set-countries':lambda:set_countries(allowed),
             'confirm':confirm,'rollback':rollback,'rollback-policy':rollback_policy,
             'status':status}
    actions[args.command]()

if __name__=='__main__':main()
