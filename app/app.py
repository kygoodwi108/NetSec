# NetSec product release v1.1.1 (dedicated Jimmy analyst workspace / PWA)
# NetSec v3.8.5 netsecadmin reverse proxy authorization
# NetSec v3.8.2 metadata token / Basic Auth separation
# NetSec v3.8 proactive source intelligence
# NetSec v3.6 active defense and autonomous verification
# NetSec v3.5 Command Hub and Connections API
# NetSec AI reliability v3.2
#!/usr/bin/env python3
# NetSec v3 intelligence
"""NetSec v2: read-only Nginx/CrowdSec dashboard; Python stdlib only."""
import collections
import html
import datetime as dt
import glob
import gzip
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import parse_qs
import netsec_homepage as KVG
import netsec_service_checks as SVC
import netsec_intel as NI  # NetSec v3 intelligence
import netsec_connections as NC  # Read-only per-IP response outcomes
import netsec_request_explorer as RX  # Sanitized per-IP HTTP requests
import netsec_source_hub as NSH  # Advisory AI source metadata and full inventory
import netsec_bans as NB  # Authenticated queue for root ban worker
import netsec_jimmy_checks as NCHK  # Read-only diagnostics and bouncer denials
import netsec_manual_refresh as NMR  # NetSec AI reliability v3.2
import netsec_proxy_auth as NPA  # Verified Nginx netsecadmin login
import netsec_jimmy_api as JAPI
import netsec_patchmon as PM

DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.environ.get('STATUS_CONFIG', os.path.join(DIR, 'config.json')), encoding='utf8') as f:
    CFG = json.load(f)
HOST = CFG.get('bind', '127.0.0.1')
PORT = int(CFG.get('port', 8787))
ASSISTANT_NAME = str(CFG.get('assistant_name', 'Jimmy'))
if not re.fullmatch(r'[A-Za-z][A-Za-z0-9 _-]{0,31}', ASSISTANT_NAME):
    raise SystemExit('Invalid assistant_name in config.json')
if HOST not in ('127.0.0.1', '::1', 'localhost') and os.environ.get('ALLOW_REMOTE_BIND') != 'YES':
    raise SystemExit('Refusing non-loopback bind without ALLOW_REMOTE_BIND=YES')
MAX_LINES = max(1000, min(int(CFG.get('max_log_lines', 50000)), 200000))
MAX_API_BYTES = 1_000_000
# Standard nginx combined format (not a host-specific access_log format).
LOG_RE = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<when>[^]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+) "[^"]*" "[^"]*"')
PROBE_RE = re.compile(r'(?:/\.env(?:[./?]|$)|/\.git(?:/|$)|/wp-login\.php|/wp-admin(?:/|$)|/phpmyadmin|/cgi-bin/|/\.aws/|/server-status|/actuator(?:/|$)|/vendor/phpunit|/etc/passwd|/boaform|/HNAP1|/\.ssh/|/config\.php|/xmlrpc\.php|/autodiscover/|/\.DS_Store|/api/.*debug)', re.I)
DATA_LOCK = threading.Lock()
CACHE = {'at': 0.0, 'value': None}
CACHE_SECONDS = 25
CENTROIDS = {}
try:
    with open(os.path.join(DIR, 'countries.json'), encoding='utf8') as f:
        CENTROIDS = json.load(f)
except (OSError, ValueError):
    pass


def _iso(value):
    return value.astimezone(dt.timezone.utc).isoformat()


def _tail_lines(path, max_lines):
    """Read uncompressed active log from its end, bounded by both bytes and lines."""
    buf = bytearray()
    with open(path, 'rb') as f:
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        while pos > 0 and buf.count(b'\n') <= max_lines and len(buf) < 30_000_000:
            n = min(65536, pos)
            pos -= n
            f.seek(pos)
            buf[:0] = f.read(n)
    return buf.decode('utf8', 'replace').splitlines()[-max_lines:]


def _lines(path):
    if path.endswith('.gz'):
        # Historical compressed logs: streaming read, 20 MB expanded hard cap per file.
        size = 0
        with gzip.open(path, 'rt', encoding='utf8', errors='replace') as f:
            for line in f:
                size += len(line)
                if size > 20_000_000:
                    return
                yield line
    else:
        yield from _tail_lines(path, MAX_LINES)


def _files():
    patterns = CFG.get('access_log_globs', ['/var/log/nginx/access.log'])
    names = set()
    for pattern in patterns:
        for path in glob.glob(pattern):
            if os.path.isfile(path) and (path.endswith('.log') or re.search(r'\.log\.\d+(?:\.gz)?$', path)):
                names.add(path)
    return sorted(names)


def _parse(line):
    match = LOG_RE.match(line)
    if not match:
        return None
    try:
        when = dt.datetime.strptime(match['when'], '%d/%b/%Y:%H:%M:%S %z').astimezone(dt.timezone.utc)
    except ValueError:
        return None
    parts = match['request'].split(' ')
    raw_target = parts[1] if len(parts) > 1 else '/'
    # Never expose URL queries, fragments, or embedded credentials in API or UI.
    path = raw_target.split('?', 1)[0].split('#', 1)[0][:190]
    if not path.startswith('/'):
        path = '[non-origin-form request]'
    return {'when': when, 'ip': match['ip'][:48], 'method': parts[0][:10] if parts else '',
            'path': path, 'status': int(match['status']), 'probe_like': bool(PROBE_RE.search(path)),
            'bytes': int(match['bytes']) if match['bytes'].isdigit() else 0}


def _load_alerts():
    path = CFG.get('crowdsec_alerts_json', '')
    if not path:
        return {'configured': False, 'alerts': []}
    try:
        if os.path.getsize(path) > MAX_API_BYTES:
            return {'configured': True, 'alerts': [], 'error': 'Alert export too large'}
        with open(path, encoding='utf8') as f:
            raw = json.load(f)
        if not isinstance(raw, list):
            raise ValueError('Bad CrowdSec JSON')
        alerts = []
        for a in raw[:100]:
            if not isinstance(a, dict):
                continue
            src = a.get('source') or {}
            alerts.append({'time': a.get('created_at'), 'scenario': str(a.get('scenario', ''))[:130],
                           'source_ip': src.get('ip') or src.get('value'),
                           'country': src.get('cn') or src.get('country')})
        return {'configured': True, 'alerts': alerts,
                'export_updated': _iso(dt.datetime.fromtimestamp(os.path.getmtime(path), dt.timezone.utc))}
    except (OSError, ValueError, TypeError):
        return {'configured': True, 'error': 'Cannot read CrowdSec alert export', 'alerts': []}


def _services():
    return SVC.sample(CFG.get('services', []))['services']


@lru_cache(maxsize=12000)
def _country(ip):
    """Offline DB-IP Lite country lookup, using a prebuilt SQLite range index."""
    try:
        address = ipaddress.ip_address(ip)
        if not address.is_global:
            return None
        db = CFG.get('geoip_db', os.path.join(DIR, 'geoip-country.sqlite3'))
        if not os.path.isfile(db):
            return None
        encoded = address.packed.rjust(16, b'\0')
        with sqlite3.connect('file:' + db + '?mode=ro', uri=True, timeout=2) as conn:
            row = conn.execute('SELECT end_ip, country FROM ip_ranges WHERE family=? AND start_ip<=? ORDER BY start_ip DESC LIMIT 1',
                               (address.version, encoded)).fetchone()
        return row[1].upper() if row and row[0] >= encoded else None
    except (ValueError, OSError, sqlite3.Error):
        return None


def _risk_traffic(traffic, cs, svc, now):
    """Heuristic indicators, not a security grade or claim of compromise."""
    recent = traffic['last_hour']
    reasons, severity = [], 0
    if traffic['log_files_readable'] == 0:
        return {'level': 'unknown', 'label': 'NO VISIBILITY', 'reasons': ['No readable Nginx logs'], 'scope': 'HTTP(S) access logs + exported CrowdSec alerts'}
    alerts_hour = []
    for a in cs.get('alerts', []):
        try:
            x = dt.datetime.fromisoformat(str(a.get('time', '')).replace('Z', '+00:00'))
            if x.tzinfo and now - dt.timedelta(hours=1) <= x.astimezone(dt.timezone.utc) <= now:
                alerts_hour.append(a)
        except ValueError:
            pass
    if alerts_hour:
        severity = 2
        reasons.append(f'{len(alerts_hour)} CrowdSec alert(s) in the last hour')
    p = recent.get('probe_like_requests', 0)
    sources = recent.get('probe_source_count', 0)
    total = recent.get('requests', 0)
    e = recent.get('http_5xx', 0)
    if p >= 30 and sources >= 3:
        severity = 2
        reasons.append(f'{p} probe-like hits from {sources} sources in 1h')
    elif p >= 5 or (p >= 3 and sources >= 2):
        severity = max(severity, 1)
        reasons.append(f'{p} probe-like requests in the last hour')
    if total >= 30 and e >= 10 and e/total >= 0.15:
        severity = 2
        reasons.append(f'Server HTTP 5xx errors: {e}/{total} requests in 1h')
    elif total >= 20 and e >= 3 and e/total >= 0.05:
        severity = max(severity, 1)
        reasons.append(f'Raised HTTP 5xx rate: {e}/{total} in 1h')
    failed_services = [s['name'] for s in svc if s['status'] in ('down', 'configuration error')]
    if failed_services:
        reasons.append('Service check(s) failed: ' + ', '.join(failed_services[:3]))
        severity = max(severity, 1)
    if cs.get('error'):
        reasons.append('CrowdSec export cannot be read')
        severity = max(severity, 1)
    if not reasons:
        reasons = ['No configured alert thresholds triggered in the last hour']
    return {'level': ('green', 'amber', 'red')[severity],
            'label': ('LOW OBSERVED RISK', 'ATTENTION', 'HIGH OBSERVED RISK')[severity],
            'reasons': reasons,
            'scope': 'Heuristic HTTP(S) indicators only; does not prove a network is secure'}




def _load_ai_assessment():
    # Always preserve successful reports; display age and last attempt separately.
    return NMR.ai_report()


def _make_snapshot(scope='all'):
    # NetSec v3 intelligence: scope applied to every parsed request and derived graph.
    now = dt.datetime.now(dt.timezone.utc)
    start_14 = now - dt.timedelta(days=14)
    start_24 = now - dt.timedelta(hours=24)
    start_1 = now - dt.timedelta(hours=1)
    files = _files()
    friendly_ips = NI.friendly_set()
    errors = []
    scanned = 0
    # Counters kept bounded; raw records stored only for 24h up to limit.
    codes = collections.Counter()
    ips = collections.Counter()
    paths = collections.Counter()
    methods = collections.Counter()
    probes_by_ip = collections.Counter()
    hours = collections.Counter()
    hours_probe = collections.Counter()
    hours_5xx = collections.Counter()
    days = collections.Counter()
    days_probe = collections.Counter()
    days_errors = collections.Counter()
    hourly_probes = collections.Counter()
    last_hour = collections.Counter()
    recent = []
    recent_probes = []
    timeline_total = 0
    for path in files:
        try:
            for line in _lines(path):
                row = _parse(line)
                if not row or row['when'] < start_14 or row['when'] > now + dt.timedelta(minutes=3):
                    continue
                if scope == 'unknown' and row['ip'] in friendly_ips:
                    continue
                scanned += 1
                day_key = row['when'].strftime('%Y-%m-%d')
                days[day_key] += 1
                if row['probe_like']:
                    days_probe[day_key] += 1
                if row['status'] >= 500:
                    days_errors[day_key] += 1
                if row['when'] < start_24:
                    continue
                timeline_total += 1
                hour_key = row['when'].strftime('%Y-%m-%dT%H:00:00+00:00')
                hours[hour_key] += 1
                if row['probe_like']:
                    hours_probe[hour_key] += 1
                if row['status'] >= 500:
                    hours_5xx[hour_key] += 1
                codes[row['status']] += 1
                ips[row['ip']] += 1
                paths[row['path']] += 1
                methods[row['method']] += 1
                if row['probe_like']:
                    probes_by_ip[row['ip']] += 1
                if row['when'] >= start_1:
                    last_hour['requests'] += 1
                    if row['probe_like']:
                        last_hour['probe_like_requests'] += 1
                        hourly_probes[row['ip']] += 1
                    if row['status'] >= 500:
                        last_hour['http_5xx'] += 1
                # Limit array size even on high volume; newest across all files later.
                row_out = {'time': _iso(row['when']), 'ip': row['ip'], 'method': row['method'],
                           'path': row['path'], 'status': row['status'], 'probe_like': row['probe_like']}
                recent.append(row_out)
                if row['probe_like']:
                    recent_probes.append(row_out)
        except (OSError, EOFError) as e:
            errors.append(f'{os.path.basename(path)}: {type(e).__name__}')
    recent.sort(key=lambda r: r['time'], reverse=True)
    recent_probes.sort(key=lambda r: r['time'], reverse=True)
    last_hour['probe_source_count'] = len(hourly_probes)
    hs = []
    for h in reversed(range(24)):
        key = (now.replace(minute=0, second=0, microsecond=0) - dt.timedelta(hours=h)).strftime('%Y-%m-%dT%H:00:00+00:00')
        hs.append({'time': key, 'requests': hours[key], 'probes': hours_probe[key], 'errors': hours_5xx[key]})
    ds = []
    for i in reversed(range(14)):
        key = (now - dt.timedelta(days=i)).strftime('%Y-%m-%d')
        ds.append({'date': key, 'requests': days[key], 'probes': days_probe[key], 'errors': days_errors[key]})
    # Country counts are geolocated locally. No visitor IP is sent to an external service.
    geo_db = CFG.get('geoip_db', os.path.join(DIR, 'geoip-country.sqlite3'))
    by_country = collections.Counter()
    mapped_req = 0
    for ip, count in ips.most_common(3000):
        country = _country(ip)
        if country:
            by_country[country] += count
            mapped_req += count
    cs = _load_alerts()
    # Generic checks are the default. A legacy homepage file is optional and
    # never required for new deployments. If a legacy feed is stale or broken,
    # use the configured direct checks instead of fabricating a service failure.
    service_monitor = SVC.sample(CFG.get('services', []))
    homepage = KVG.feed(CFG.get('homepage_status_file'), CFG.get('homepage_max_age_seconds', 150)) if CFG.get('homepage_status_file') else None
    svc, service_source = KVG.select_services(homepage, service_monitor)
    geo_rows = []
    for code, count in by_country.most_common(35):
        c = CENTROIDS.get(code)
        if c:
            geo_rows.append({'code': code, 'country': c['name'], 'lat': c['lat'], 'lon': c['lon'], 'requests': count})
    traffic = {
        'log_files_found': len(files), 'log_files_readable': len(files) - len(errors), 'log_errors': errors,
        'period': 'Past 24h, within available log tails. 14-day trends need rotated logs.',
        'requests': timeline_total, 'unique_ips': len(ips),
        'http_401': codes[401], 'http_403': codes[403], 'http_404': codes[404],
        'http_5xx': sum(n for k, n in codes.items() if k >= 500),
        'probe_like_requests': sum(probes_by_ip.values()),
        'status_codes': [{'status': k, 'count': v} for k, v in codes.most_common(16)],
        'top_ips': [{'ip': ip, 'requests': n} for ip, n in ips.most_common(15)],
        'top_paths': [{'path': p, 'requests': n} for p, n in paths.most_common(20)],
        'probe_sources': [{'ip': ip, 'requests': n} for ip, n in probes_by_ip.most_common(15)],
        'methods': [{'method': m, 'count': n} for m, n in methods.most_common(10)],
        'recent_requests': recent[:120], 'recent_probes': recent_probes[:80],
        'hourly': hs, 'daily': ds, 'last_hour': dict(last_hour),
        'bytes_note': 'Bandwidth not estimated; response sizes may exclude TLS/overhead',
        'note': 'Scan paths are heuristic indicators. HTTP 401/403/404 alone do not prove malicious behaviour.'
    }
    geo = {'enabled': os.path.isfile(geo_db), 'database': 'DB-IP Country Lite, offline' if os.path.isfile(geo_db) else 'Not installed',
           'countries': geo_rows, 'mapped_requests': mapped_req, 'total_requests': timeline_total,
           'scope': 'Approximate country of network IP, not the visitor\'s physical location. Private IPs excluded.',
           'attribution': 'IP geolocation by DB-IP.com (CC BY 4.0)'}
    return {'generated_at': _iso(now), 'version': installed_version(), 'host': str(CFG.get('display_name', 'Home Server'))[:100],
            'traffic': traffic, 'geo': geo, 'risk': _risk_traffic(traffic, cs, svc, now),
            'services': svc, 'homepage': homepage, 'service_monitor': service_monitor,
            'service_source': service_source, 'crowdsec': cs, 'ai': _load_ai_assessment(),
            'scope': 'Nginx HTTP(S) logs plus optional exported CrowdSec; not SSH/firewall/VPN audit data.'}


def installed_version():
    """Read the actual deployed release marker, not an outdated UI string."""
    for path in (Path(__file__).resolve().parent / 'VERSION', Path('/etc/netsec-installed-version')):
        try:
            value=path.read_text(encoding='utf-8').strip()
            if re.fullmatch(r'1\.[0-9]+\.[0-9]+', value):
                return value
        except OSError:
            continue
    return 'unknown'


def snapshot(scope='unknown'):
    if scope not in ('unknown','all'):
        scope='unknown'
    with DATA_LOCK:
        if CACHE['value'] is None or time.monotonic()-CACHE['at'] >= CACHE_SECONDS:
            # All and unknown are separate read-only views of the SAME log sources.
            # The scoped aggregates are recomputed every 25 seconds; raw logs unchanged.
            all_data=_make_snapshot('all')
            unknown_data=_make_snapshot('unknown')
            CACHE.update(value={'all':all_data,'unknown':unknown_data},at=time.monotonic())
        both=CACHE['value']
        focused=dict(both[scope])
        focused['intel']=NI.public_metadata(scope,both['all'],both['unknown'])
        focused['enforcement']=NI.read_enforcement()
        focused['scope_note']='Traffic/chart/map/log views obey scope. CrowdSec alerts and service checks remain global security signals.'
        return focused


def NSH_send(handler, status, payload):
    body=json.dumps(payload,ensure_ascii=False,separators=(',',':')).encode('utf8')
    handler.send_response(status)
    handler.send_header('Content-Type','application/json; charset=utf-8')
    handler.send_header('Cache-Control','no-store')
    handler.send_header('X-Content-Type-Options','nosniff')
    handler.send_header('Content-Length',str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split('?', 1)[0]
        if path in ('/api/jimmy/workspace','/api/push/status'):
            return JAPI.get(self,path)
        if path == '/api/integrations/patchmon':
            if not NPA.require(self,write=False):return
            return JAPI.send(self,200,PM.status(CFG.get('patchmon_url')))
        if path == '/api/ai/refresh-state':
            return NMR.get_status(self)
        if path == '/api/operator/session':
            if not NPA.require(self,write=False): return
            return NSH_send(self,200,{'ok':True,'user':NPA._settings()['user'],'mode':'nginx-basic'})
        if path == '/api/ban/job':
            return NB.result(self)
        if path == '/api/defense/recent':
            try:
                out={'ok':True,'denials':NCHK.recent_bouncer_blocks(),
                     'decisions':(NI.read_enforcement().get('decisions') or [])[:75]}
                NB._send(self,200,out)
            except Exception:
                NB._send(self,503,{'ok':False,'error':'Enforcement evidence not available'})
            return
        if path == '/api/source-hub':
            try:
                query=parse_qs(self.path.partition('?')[2])
                data=NSH.inventory(_files,_lines,_parse,_country,query)
                return NSH_send(self,200,data)
            except (ValueError,TypeError):
                return NSH_send(self,400,{'ok':False,'error':'Invalid source inventory query'})
            except Exception as exc:
                print('NetSec source hub error:',type(exc).__name__,flush=True)
                return NSH_send(self,503,{'ok':False,'error':'Source inventory temporarily unavailable'})
        if path == '/api/source-requests':
            if not NPA.require(self,write=False):return
            try:
                query=parse_qs(self.path.partition('?')[2])
                field=lambda key,default:query.get(key,[default])[0]
                data=RX.explore(_files,_lines,_parse,field('ip',''),window=field('window','24h'),
                                offset=field('offset','0'),limit=field('limit','100'),
                                status=field('status','all'),search=field('search',''))
                return NSH_send(self,200,data)
            except (ValueError,TypeError) as ex:
                return NSH_send(self,400,{'ok':False,'error':str(ex)[:120]})
            except (OSError,UnicodeError) as ex:
                print('Source explorer error:',type(ex).__name__,flush=True)
                return NSH_send(self,503,{'ok':False,'error':'Request history unavailable'})
        if path == '/api/source-labels':
            if not NPA.require(self,write=False):return
            try:
                meta=NI.read_registry().get('addresses',{})
                return NSH_send(self,200,{'ok':True,'labels':dict(list(meta.items())[:1000]),
                                           'ai':dict(list(NSH.stored_ai().items())[:1000])})
            except (OSError,ValueError):
                return NSH_send(self,503,{'ok':False,'error':'Source labels unavailable'})
        if path == '/api/connections':
            try:
                params=parse_qs(self.path.partition('?')[2])
                window=params.get('window',['24h'])[0]
                scope=params.get('scope',['all'])[0]
                # A separate 90-second cache keeps additional log scans bounded.
                connection_data=NC.snapshot(_files,_lines,_parse,NI.friendly_set,_country,
                                            window=window,scope=scope,limit=300)
                b=json.dumps(connection_data,ensure_ascii=False,separators=(',',':')).encode('utf8')
                self.send_response(200)
            except ValueError:
                b=b'{"error":"Invalid connections query"}'
                self.send_response(400)
            except Exception as e:
                print('NetSec connections API error:',repr(e),flush=True)
                b=b'{"error":"Connections unavailable; check service journal"}'
                self.send_response(500)
            mime='application/json; charset=utf-8'
        elif path == '/api/status':
            try:
                scope = parse_qs(self.path.partition('?')[2]).get('scope',['unknown'])[0]
                b = json.dumps(snapshot(scope), ensure_ascii=False).encode('utf8')
                self.send_response(200)
            except Exception as e:
                print('NetSec API error:', repr(e), flush=True)
                b = b'{"error":"Cannot compute status; check service journal"}'
                self.send_response(500)
            mime = 'application/json; charset=utf-8'
        elif path in ('/', '/index.html', '/world.svg', '/manifest.webmanifest',
                      '/sw.js', '/jimmy-ui.js', '/jimmy-action-plan.js', '/netsec-v13.js', '/mobile-ui.js', '/mobile.css', '/offline.html', '/icon-192.png', '/icon-512.png'):
            name = 'index.html' if path in ('/', '/index.html') else path.lstrip('/')
            with open(os.path.join(DIR, name), 'rb') as f:
                b = f.read()
            if name in ('index.html','manifest.webmanifest'):
                safe_name = html.escape(ASSISTANT_NAME)
                b = b.decode('utf8').replace('Jimmy', safe_name).replace('JIMMY', safe_name.upper()).encode('utf8')
            self.send_response(200)
            mime = {'index.html':'text/html; charset=utf-8',
                    'offline.html':'text/html; charset=utf-8',
                    'world.svg':'image/svg+xml', 'sw.js':'text/javascript; charset=utf-8',
                    'jimmy-ui.js':'text/javascript; charset=utf-8',
                    'jimmy-action-plan.js':'text/javascript; charset=utf-8',
                    'netsec-v13.js':'text/javascript; charset=utf-8',
                    'mobile-ui.js':'text/javascript; charset=utf-8',
                    'mobile.css':'text/css; charset=utf-8',
                    'manifest.webmanifest':'application/manifest+json',
                    'icon-192.png':'image/png', 'icon-512.png':'image/png'}[name]
        else:
            self.send_error(404)
            return
        self.send_header('Content-Type', mime)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        path=self.path.partition('?')[0]
        if path.startswith('/api/jimmy/') or path.startswith('/api/push/'):
            return JAPI.post(self,path)
        if self.path.partition('?')[0]=='/api/ban':
            return NB.trigger(self)
        if self.path.partition('?')[0]=='/api/ai/refresh':
            return NMR.do_trigger(self)
        if self.path.partition('?')[0]!='/api/intel/label':
            self.send_error(404); return
        if not NPA.require(self,write=True): return
        try:
            length=int(self.headers.get('Content-Length','0'))
            if length<2 or length>2048:raise ValueError('Invalid request size')
            body=json.loads(self.rfile.read(length).decode('utf8'))
            if not isinstance(body,dict): raise ValueError('Expected JSON object')
            ip=body.get('ip'); status=body.get('status')
            label=body.get('label',''); note=body.get('note','')
            result=NI.set_label(ip,status,label,note)
            with DATA_LOCK:
                CACHE.update(value=None,at=0)
            result_body=json.dumps({'ok':True,'ip':NI.canonical_ip(ip),'metadata':result}).encode('utf8')
            self.send_response(200)
        except (ValueError,TypeError,UnicodeError,OSError) as e:
            result_body=json.dumps({'ok':False,'error':str(e)[:160]}).encode('utf8')
            self.send_response(400)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Length',str(len(result_body)))
        self.end_headers()
        self.wfile.write(result_body)

    def log_message(self, fmt, *args):
        print('netsec', self.address_string(), fmt % args, flush=True)


if __name__ == '__main__':
    print(f'NetSec dashboard on {HOST}:{PORT}', flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()

# X-NetSec-Admin-Token v3.2 build precondition
