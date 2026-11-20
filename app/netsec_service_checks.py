#!/usr/bin/env python3
"""Generic, read-only HTTP(S) and TCP reachability checks.

No API keys, no dependence on a personal homepage, and no Proxmox API privileges.
Configured by a local administrator in config.json; statuses measure reachability,
not whether a VM/container is running or its application is healthy internally.
"""
import concurrent.futures
import datetime as dt
import ipaddress
import re
import socket
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

MAX_CHECKS = 25
TIMEOUT_SECONDS = 2.5
CACHE_SECONDS = 25
_LOCK = threading.Lock()
_CACHE = {'until': 0, 'key': None, 'value': None}


def validate(item):
    if not isinstance(item, dict):
        raise ValueError('Service check must be an object')
    name = item.get('name')
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 75 or any(ord(c)<32 for c in name):
        raise ValueError('Invalid service name')
    kind = item.get('type', 'http' if item.get('url') else 'tcp')
    if kind == 'http':
        url = item.get('url', '')
        if not isinstance(url, str) or len(url) > 300:
            raise ValueError('Invalid HTTP target')
        p = urlsplit(url)
        try:
            port=p.port
        except ValueError:
            raise ValueError('Invalid HTTP port') from None
        if (p.scheme not in ('http','https') or not p.hostname or p.username or p.password
                or p.fragment or (port is not None and not 1 <= port <= 65535)):
            raise ValueError('Invalid HTTP URL; no userinfo or fragment allowed')
        if any(c.isspace() or ord(c) < 32 for c in url):
            raise ValueError('Invalid HTTP URL characters')
        return {'name': name.strip(), 'type':'http','url':url}
    if kind == 'tcp':
        host = item.get('host', '')
        port = item.get('port')
        if not isinstance(host,str) or len(host)>253 or not host or any(c.isspace() for c in host):
            raise ValueError('Invalid TCP host')
        if host.startswith('[') and host.endswith(']'):
            host=host[1:-1]
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}',host):
                raise ValueError('Invalid hostname')
        if isinstance(port,bool) or not isinstance(port,int) or not 1 <= port <= 65535:
            raise ValueError('Invalid TCP port')
        return {'name':name.strip(),'type':'tcp','host':host,'port':port}
    raise ValueError('Check type must be http or tcp')


def _one(raw):
    name=str(raw.get('name','Service'))[:75] if isinstance(raw,dict) else 'Service'
    try:
        item=validate(raw)
    except (ValueError, TypeError):
        return {'name':name,'status':'configuration error','source':'netsec','type':'invalid'}
    start=time.monotonic()
    if item['type']=='http':
        try:
            with urlopen(Request(item['url'],headers={'User-Agent':'NetSecServiceCheck/1.0'}),timeout=TIMEOUT_SECONDS) as resp:
                code=resp.status
            status='up' if code < 500 else 'down'
            return {'name':name,'status':status,'http_code':code,'type':'http','source':'netsec',
                    'latency_ms':round((time.monotonic()-start)*1000)}
        except HTTPError as exc:
            # A 401 or 403 often means the server is online and requires login.
            return {'name':name,'status':'up' if exc.code < 500 else 'down',
                    'http_code':exc.code,'type':'http','source':'netsec',
                    'latency_ms':round((time.monotonic()-start)*1000)}
        except (OSError,URLError,TimeoutError,ValueError):
            return {'name':name,'status':'down','type':'http','source':'netsec'}
    try:
        with socket.create_connection((item['host'],item['port']),timeout=TIMEOUT_SECONDS):
            pass
        return {'name':name,'status':'up','type':'tcp','source':'netsec',
                'latency_ms':round((time.monotonic()-start)*1000)}
    except (OSError,TimeoutError,ValueError):
        return {'name':name,'status':'down','type':'tcp','source':'netsec'}


def run(items):
    """Bounded parallel checks and short cache; callers get one consistent sample."""
    if not isinstance(items, list):
        return []
    selected=items[:MAX_CHECKS]
    if not selected:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8,len(selected))) as pool:
        return list(pool.map(_one, selected))


def sample(items):
    if not isinstance(items,list):
        items=[]
    key=repr(items[:MAX_CHECKS])
    now=time.monotonic()
    with _LOCK:
        if _CACHE['key']==key and _CACHE['until']>now:
            return _CACHE['value']
    result={'state':'checked' if items else 'not_configured','source':'NetSec built-in service checks',
            'checked_at':dt.datetime.now(dt.timezone.utc).isoformat(),
            'services':run(items)}
    with _LOCK:
        _CACHE.update({'key':key,'until':time.monotonic()+CACHE_SECONDS,'value':result})
    return result
