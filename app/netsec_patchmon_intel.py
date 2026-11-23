#!/usr/bin/env python3
"""Read-only PatchMon host intelligence for the NetSec Command Hub and Jimmy.

Fixed HTTPS destination; no model-directed fetches, redirects, patch jobs or mutation.
Credentials are kept in a service-readable, root-managed file outside the app.
"""
import ipaddress
import base64
import datetime as dt
import json
import os
import re
import threading
import time
from pathlib import Path
from http.client import HTTPSConnection
import socket
import ssl

CREDENTIALS = Path('/etc/netsec-patchmon-readonly.json')
ENDPOINT = Path('/etc/netsec-patchmon-endpoint.json')

def endpoint(host, address):
    if not isinstance(host, str) or len(host) > 253 or not all(
            re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
            for label in host.split('.')):
        raise ValueError('Invalid TLS hostname')
    ip = ipaddress.ip_address(address)
    if not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        raise ValueError('Expected a private proxy IP')
    return host.lower(), str(ip)
CACHE_SEC = 45
MAX_DATA = 800_000
_lock = threading.Lock()
_cache = {'stamp': 0.0, 'value': None}
_UUID = re.compile(r'^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')


class PatchMonHTTPError(Exception):
    def __init__(self, code):
        super().__init__('PatchMon API HTTP ' + str(code))
        self.code = code


class LocalVerifiedTLS(HTTPSConnection):
    """Connect to local Nginx while authenticating its real PatchMon TLS hostname."""
    def __init__(self, target):
        host, self.proxy_ip = target
        super().__init__(host, 443, timeout=4, context=ssl.create_default_context())

    def connect(self):
        raw = socket.create_connection((self.proxy_ip, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def _text(value, limit=90):
    return re.sub(r'[\x00-\x1f\x7f]', ' ', str(value or ''))[:limit]


def _count(value):
    if isinstance(value, bool):
        return None
    try:
        n = int(value)
        return max(0, min(n, 1_000_000)) if n >= 0 else None
    except (ValueError, TypeError, OverflowError):
        return None


def _credentials():
    try:
        s = CREDENTIALS.stat()
        if s.st_size > 4096 or s.st_mode & 0o027 or s.st_uid != 0:
            raise ValueError('Unsafe permissions or size on API credential file')
        data = json.loads(CREDENTIALS.read_text(encoding='utf8'))
        api_id = data['api_id']; api_secret = data['api_secret']
        if not isinstance(api_id, str) or not isinstance(api_secret, str):
            raise ValueError('Invalid API credentials')
        if not 8 <= len(api_id) <= 160 or ':' in api_id or not 12 <= len(api_secret) <= 512:
            raise ValueError('Invalid API credential format')
        settings = data if 'hostname' in data or 'proxy_ip' in data else json.loads(ENDPOINT.read_text())
        return (api_id, api_secret), endpoint(settings['hostname'], settings['proxy_ip'])
    except FileNotFoundError:
        return None


def _get(path, creds, target):
    # Caller can only choose one of two fixed REST endpoint forms.
    if path != '/api/v1/api/hosts?include=stats' and not re.fullmatch(
            r'/api/v1/api/hosts/[0-9a-fA-F-]{36}/packages\?updates_only=true', path):
        raise ValueError('Unapproved PatchMon path')
    token = base64.b64encode((creds[0] + ':' + creds[1]).encode()).decode('ascii')
    conn = LocalVerifiedTLS(target)
    try:
        conn.request('GET', path, headers={
            'Authorization': 'Basic ' + token,
            'Accept': 'application/json',
            'User-Agent': 'NetSec-PatchMon-ReadOnly/1.0',
        })
        reply = conn.getresponse()
        if reply.status != 200:
            # There are no redirect handlers, nor arbitrary destinations.
            raise PatchMonHTTPError(reply.status)
        body = reply.read(MAX_DATA + 1)
        if len(body) > MAX_DATA:
            raise ValueError('PatchMon response exceeds safe size limit')
        result = json.loads(body)
    finally:
        conn.close()
    if not isinstance(result, dict):
        raise ValueError('Unexpected PatchMon response format')
    return result


def _fresh():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')


def _load_snapshot(target, creds):
    result = {'ok': True, 'configured': True, 'mode': 'read_only',
              'api_source': 'PatchMon scoped API host:get', 'public_url': 'https://' + target[0],
              'checked_at': _fresh()}
    try:
        response = _get('/api/v1/api/hosts?include=stats', creds, target)
        raw_hosts = response.get('hosts')
        if not isinstance(raw_hosts, list):
            raise ValueError('PatchMon returned no host list')
        total = _count(response.get('total'))
        hosts = []
        for raw in raw_hosts[:100]:
            if not isinstance(raw, dict):
                continue
            hosts.append({
                'id': _text(raw.get('id'), 36),
                'name': _text(raw.get('friendly_name') or raw.get('hostname') or 'Unnamed host', 80),
                'ip': _text(raw.get('ip'), 48),
                'os': _text(' '.join(filter(None, [str(raw.get('os_type') or ''), str(raw.get('os_version') or '')])), 80),
                'reporting': _text(raw.get('reporting_state') or 'unknown', 24),
                'effective_status': _text(raw.get('effective_status') or raw.get('status') or 'unknown', 24),
                'update_state': _text(raw.get('update_state') or 'unknown', 28),
                'security_updates': _count(raw.get('security_updates_count')),
                'updates': _count(raw.get('updates_count')),
                'needs_reboot': raw.get('needs_reboot') is True,
                'last_reported': _text(raw.get('last_update'), 50),
                'packages': [],
            })
        # Security updates are prioritized, then other pending updates, then stale agents.
        hosts.sort(key=lambda h:(
            -(h['security_updates'] or 0),
            -(h['updates'] or 0),
            h['reporting'] not in ('stale', 'overdue'), h['name'].lower()))
        # Use at most four additional GET requests to see *which* packages need updating.
        # A separate endpoint failure leaves the inventory usable and is flagged as a coverage gap.
        detail_errors = 0
        for host in [h for h in hosts if h['updates'] and _UUID.fullmatch(h['id'])][:4]:
            try:
                details = _get('/api/v1/api/hosts/' + host['id'] + '/packages?updates_only=true', creds, target)
                packages = details.get('packages')
                if not isinstance(packages, list):
                    raise ValueError('No package data')
                for item in packages[:12]:
                    if not isinstance(item, dict):
                        continue
                    host['packages'].append({
                        'name': _text(item.get('name'), 85),
                        'current_version': _text(item.get('current_version'), 65),
                        'available_version': _text(item.get('available_version'), 65),
                        'security': item.get('is_security_update') is True,
                    })
            except (PatchMonHTTPError, OSError, TimeoutError, ValueError, json.JSONDecodeError):
                detail_errors += 1
        return {**result, 'state': 'ready', 'total_hosts': total if total is not None else len(raw_hosts),
                'displayed_hosts': len(hosts), 'partial': len(raw_hosts) > len(hosts) or
                (total is not None and total > len(raw_hosts)),
                'security_updates': sum(h['security_updates'] or 0 for h in hosts),
                'updates': sum(h['updates'] or 0 for h in hosts),
                'hosts_with_security_updates': sum((h['security_updates'] or 0) > 0 for h in hosts),
                'hosts_with_updates': sum((h['updates'] or 0) > 0 for h in hosts),
                'hosts_stale_or_overdue': sum(h['reporting'] in ('stale', 'overdue') for h in hosts),
                'hosts_need_reboot': sum(h['needs_reboot'] for h in hosts),
                'detail_fetch_failures': detail_errors, 'hosts': hosts}
    except PatchMonHTTPError as error:
        if error.code in (401, 403):
            return {**result, 'state': 'access_denied', 'http_code': error.code,
                    'reason': 'PatchMon denied scoped API access; verify API credentials and host:get scope'}
        return {**result, 'state': 'api_error', 'http_code': error.code,
                'reason': 'PatchMon API responded with an error'}
    except (OSError, TimeoutError, ValueError, json.JSONDecodeError) as error:
        return {**result, 'state': 'unavailable', 'error_type': type(error).__name__,
                'reason': 'Cannot retrieve authenticated PatchMon inventory over HTTPS'}


def snapshot(configured_url=None, force=False):
    if configured_url is None:
        try:
            path = os.environ.get('STATUS_CONFIG', '/opt/server-status/config.json')
            configured_url = json.loads(Path(path).read_text()).get('patchmon_url')
        except (OSError, ValueError, TypeError):
            configured_url = None
    if not configured_url:
        return {'ok': True, 'configured': False, 'state': 'not_configured',
                'reason': 'PatchMon is not configured in NetSec'}
    # Existing config must retain the previous safe, private-IP only URL restriction.
    try:
        import netsec_patchmon as old
        old.validate(configured_url)
    except (ValueError, TypeError, ImportError):
        return {'ok': True, 'configured': False, 'state': 'invalid_config',
                'reason': 'Invalid private PatchMon address'}
    try:
        connection = _credentials()
    except (OSError, TypeError, KeyError, ValueError):
        return {'ok': True, 'configured': True, 'state': 'credential_error',
                'reason': 'Check root-managed PatchMon credentials and TLS endpoint'}
    if connection is None:
        return {**old.status(configured_url), 'state': 'reachability_only',
                'public_url': configured_url, 'reason': 'Configure the scoped API for host inventory'}
    creds, target = connection
    now = time.monotonic()
    with _lock:
        if (not force and _cache['value'] is not None
                and _cache.get('target') == target
                and now - _cache['stamp'] < CACHE_SEC):
            return dict(_cache['value'])
    data = _load_snapshot(target, creds)
    with _lock:
        _cache.update(target=target, stamp=time.monotonic(), value=data)
    return dict(data)


def for_model(data):
    if data.get('state') != 'ready':
        return {'state': data.get('state', 'unavailable'),
                'reason': data.get('reason', 'PatchMon inventory unavailable'),
                'provenance': 'Read-only PatchMon API; no inventory evidence obtained'}
    hosts = []
    for h in data.get('hosts', [])[:6]:
        hosts.append({k: h.get(k) for k in ('name', 'ip', 'reporting', 'effective_status',
            'update_state', 'security_updates', 'updates', 'needs_reboot', 'last_reported')})
        hosts[-1]['pending_packages'] = h.get('packages', [])[:3]
    return {'state': 'ready', 'source': 'PatchMon host:get scoped read-only API',
            'checked_at': data.get('checked_at'), 'total_hosts': data.get('total_hosts'),
            'security_updates': data.get('security_updates'), 'updates': data.get('updates'),
            'hosts_stale_or_overdue': data.get('hosts_stale_or_overdue'),
            'hosts_need_reboot': data.get('hosts_need_reboot'),
            'coverage': {'partial': data.get('partial'), 'detail_fetch_failures': data.get('detail_fetch_failures')},
            'hosts': hosts,
            'limitations': 'Pending updates are not proof of exploitability or compromise; avoid CVE claims unless supported by package-specific evidence. Agent data can be stale. No changes may be executed.'}
