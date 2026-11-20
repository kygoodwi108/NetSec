#!/usr/bin/env python3
"""NetSec v3.5: bounded, read-only per-IP HTTP outcome analytics.

No claim of authenticated access or exploitation is derived from HTTP statuses.
No query strings, headers, cookies or request bodies are processed or exported.
"""
import collections
import datetime as dt
import ipaddress
import os
import re
import threading
import time

WINDOWS = {'1h': dt.timedelta(hours=1), '24h': dt.timedelta(hours=24), '7d': dt.timedelta(days=7)}
SENSITIVE_PATH = re.compile(
    r'(^|/)(?:\.env(?:$|\.|/)|\.git(?:/|$)|\.svn(?:/|$)|\.aws(?:/|$)|'
    r'\.ssh(?:/|$)|(?:secrets|variables)\.pkrvars\.hcl$|'
    r'(?:credentials|secrets)\.(?:json|ya?ml)$|'
    r'config\.(?:json|ya?ml|php)$|wp-config\.php$|'
    r'backup\.(?:zip|tar|tar\.gz|tgz)$)', re.I)
_LOCK = threading.Lock()
_CACHE = {'at': 0.0, 'stats': None}
CACHE_SECONDS = 90
MAX_IPS = 25000
MAX_RECORDS = 300000


def _valid_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return None


def _counter():
    return collections.Counter()


def _record(counts, status, probe):
    counts['requests'] += 1
    if 200 <= status <= 299:
        counts['http_2xx'] += 1
        if probe:
            counts['probe_2xx'] += 1
    elif 300 <= status <= 399:
        counts['http_3xx'] += 1
    elif status in (401, 403):
        counts['denied_401_403'] += 1
    elif status == 404:
        counts['not_found_404'] += 1
    elif status >= 500:
        counts['http_5xx'] += 1
    else:
        counts['other'] += 1
    if probe:
        counts['probe_like'] += 1


def collect(files, lines, parse, now=None):
    """Scan existing bounded NetSec log sources ONCE, build all three windows."""
    now = now or dt.datetime.now(dt.timezone.utc)
    floors = {w: now-d for w,d in WINDOWS.items()}
    result = {'by_ip': {}, 'global': {w: _counter() for w in WINDOWS},
              'first_seen': None, 'last_seen': None, 'log_files': 0, 'errors': [], 'truncated_sources': True, 'ip_limit_hit': False, 'records': 0}
    for filename in files():
        try:
            if not os.path.isfile(filename):
                continue
            result['log_files'] += 1
            for raw in lines(filename):
                result['records'] += 1
                if result['records'] > MAX_RECORDS:
                    result['errors'].append('Record scan limit reached; some historical requests omitted')
                    return result
                r = parse(raw)
                if not r or r['when'] < floors['7d'] or r['when'] > now + dt.timedelta(minutes=3):
                    continue
                ip = _valid_ip(r.get('ip'))
                if ip is None:
                    continue
                when = r['when']
                if ip not in result['by_ip']:
                    if len(result['by_ip']) >= MAX_IPS:
                        if not result['ip_limit_hit']:
                            result['errors'].append('Distinct-IP limit reached; connection overview is incomplete')
                            result['ip_limit_hit'] = True
                        continue
                    result['by_ip'][ip] = {'windows': {w:_counter() for w in WINDOWS},
                                           'last_seen': when, 'top_paths': _counter(),
                                           'probe_2xx_paths': _counter()}
                item = result['by_ip'][ip]
                if when > item['last_seen']:
                    item['last_seen'] = when
                if result['first_seen'] is None or when < result['first_seen']:
                    result['first_seen'] = when
                if result['last_seen'] is None or when > result['last_seen']:
                    result['last_seen'] = when
                status = int(r['status'])
                path = str(r.get('path') or '/')[:190]
                probe = bool(r.get('probe_like')) or bool(SENSITIVE_PATH.search(path))
                if path in item['top_paths'] or len(item['top_paths']) < 160:
                    item['top_paths'][path] += 1
                if probe and 200 <= status < 300:
                    if path in item['probe_2xx_paths'] or len(item['probe_2xx_paths']) < 80:
                        item['probe_2xx_paths'][path] += 1
                for window, cutoff in floors.items():
                    if when >= cutoff:
                        _record(item['windows'][window],status,probe)
                        _record(result['global'][window],status,probe)
        except (OSError, EOFError, UnicodeError, ValueError) as exc:
            result['errors'].append(os.path.basename(filename)+': '+type(exc).__name__)
    return result


def snapshot(files, lines, parse, friendly_ips, country, window='24h', scope='all', limit=180):
    if window not in WINDOWS:
        raise ValueError('Unsupported window')
    if scope not in ('all', 'unknown', 'friendly'):
        raise ValueError('Unsupported scope')
    limit = max(1, min(int(limit), 300))
    with _LOCK:
        if _CACHE['stats'] is None or (time.monotonic()-_CACHE['at']) >= CACHE_SECONDS:
            # A failure never leaves partially populated cached data.
            new_stats=collect(files,lines,parse)
            _CACHE.update(stats=new_stats, at=time.monotonic())
        base=_CACHE['stats']
    friendly = set(friendly_ips())
    all_rows=[]
    totals={w: _counter() for w in WINDOWS}
    for ip,item in base['by_ip'].items():
        is_friendly = ip in friendly
        if scope == 'friendly' and not is_friendly:
            continue
        if scope == 'unknown' and is_friendly:
            continue
        for w in WINDOWS:
            totals[w].update(item['windows'][w])
        if not item['windows'][window]['requests']:
            continue
        all_rows.append((ip,item,is_friendly))
    all_rows.sort(key=lambda r: (
        -r[1]['windows'][window]['requests'],
        -r[1]['windows'][window]['probe_2xx'],
        r[0]))
    top = []
    for ip, item, is_friendly in all_rows[:limit]:
        c = country(ip)
        top.append({
            'ip': ip, 'friendly': is_friendly, 'country': c,
            'last_seen': item['last_seen'].isoformat(),
            'windows': {w: dict(item['windows'][w]) for w in WINDOWS},
            'top_paths': [{'path':p,'requests':n} for p,n in item['top_paths'].most_common(5)],
            'probe_2xx_paths': [{'path':p,'requests':n} for p,n in item['probe_2xx_paths'].most_common(5)]
        })
    return {
        'window': window, 'scope': scope, 'generated_at': dt.datetime.now(dt.timezone.utc).isoformat(),
        'rows_returned': len(top), 'matching_ips': len(all_rows), 'truncated': len(all_rows)>len(top),
        'windows': {w: dict(totals[w]) for w in WINDOWS},
        'ips': top,
        'coverage': {
            'log_files': base['log_files'],
            'earliest_observed': base['first_seen'].isoformat() if base['first_seen'] else None,
            'latest_observed': base['last_seen'].isoformat() if base['last_seen'] else None,
            'warnings': base['errors'][:8],
            'note': 'Observed log data only; existing NetSec log reads are line/byte bounded, and per-IP displayed paths are sampled. The 7-day window may be partial if rotated logs are unavailable.'
        },
        'definitions': {
            'served_2xx': 'HTTP 2xx: an HTTP response was served. NOT proof of authentication, data disclosure, or attacker success.',
            'redirected_3xx': 'HTTP 3xx: redirect, not treated as a successful attack.',
            'denied_401_403': 'HTTP 401/403: authentication challenge or denied response; not necessarily a CrowdSec ban.',
            'probe_2xx': 'Probe-like request receiving 2xx; inspect exact response before concluding any exposure.'
        }
    }
