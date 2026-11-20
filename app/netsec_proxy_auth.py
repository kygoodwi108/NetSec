#!/usr/bin/env python3
"""Verify Nginx-authenticated operator for dashboard actions.

Nginx must set X-NetSec-Authenticated-User to $remote_user ONLY after
successful auth_basic and override client-supplied headers in the proxied
location. The app ALSO pins the TCP peer to the configured trusted proxy IP.
This module is intentionally separate from CrowdSec and model credentials.
"""
import ipaddress
import json
from pathlib import Path
from urllib.parse import urlsplit

CONFIG=Path('/etc/netsec-proxy-auth.json')


def _settings():
    try:
        d=json.loads(CONFIG.read_text(encoding='utf8'))
        proxy_ip=str(ipaddress.ip_address(d['trusted_proxy_ip']))
        user=d.get('username')
        origin=d.get('origin')
        if not isinstance(user,str) or not 1<=len(user)<=64 or any(c.isspace() for c in user):
            return None
        if not isinstance(origin,str): return None
        parsed=urlsplit(origin)
        if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ('','/') or parsed.query or parsed.fragment:
            return None
        if parsed.port not in (None,443): return None
        return {'ip':proxy_ip,'user':user,'origin':origin.rstrip('/'), 'hostname':parsed.hostname.lower()}
    except (ValueError,TypeError,KeyError,OSError):
        return None


def is_authenticated(handler):
    cfg=_settings()
    if cfg is None:
        return False
    try:
        peer=str(ipaddress.ip_address(handler.client_address[0]))
    except (ValueError,TypeError,IndexError,AttributeError):
        return False
    if peer!=cfg['ip']:
        return False
    # Reject duplicates, comma-joined values and spoofed browser-supplied values.
    identity=handler.headers.get_all('X-NetSec-Authenticated-User', [])
    return identity==[cfg['user']]


def _valid_action(handler):
    if handler.headers.get_all('X-NetSec-Action', [])!=['dashboard']:
        return False
    cfg=_settings()
    if cfg is None:
        return False
    # Nginx auth_basic is ambient browser authority; refuse cross-site writes.
    site=handler.headers.get('Sec-Fetch-Site','')
    if site not in ('', 'same-origin', 'none'):
        return False
    origin=handler.headers.get('Origin','')
    if origin and origin!=cfg['origin']:
        return False
    # Require exactly the expected hostname for write actions.
    host=handler.headers.get('Host','').lower()
    return host==cfg['hostname']


def require(handler,write=False):
    if not is_authenticated(handler):
        _denied(handler,'Authenticate through the configured NetSec HTTPS proxy')
        return False
    if write and not _valid_action(handler):
        _denied(handler,'Invalid dashboard action origin')
        return False
    return True


def _denied(handler, message):
    # Do NOT send WWW-Authenticate, which would trigger the browser login popup.
    body=json.dumps({'ok':False,'error':message}).encode('utf8')
    handler.send_response(403)
    handler.send_header('Content-Type','application/json; charset=utf-8')
    handler.send_header('Cache-Control','no-store')
    handler.send_header('X-Content-Type-Options','nosniff')
    handler.send_header('Content-Length',str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)
