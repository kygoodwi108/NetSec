#!/usr/bin/env python3
"""Read-only, admin-configured PatchMon availability; no API keys or patch execution."""
import ipaddress
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        return None

def validate(raw):
    if raw is None or raw == '':
        return None
    if not isinstance(raw,str) or len(raw)>180:
        raise ValueError('Invalid PatchMon URL')
    p=urlsplit(raw)
    if p.scheme not in ('http','https') or not p.hostname or p.username or p.password or p.path not in ('','/') or p.query or p.fragment:
        raise ValueError('PatchMon must be an HTTP(S) private IP URL without credentials or paths')
    ip=ipaddress.ip_address(p.hostname)
    if not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        raise ValueError('PatchMon must be on a private, non-loopback IP')
    port=p.port
    if port is not None and not 1<=port<=65535:
        raise ValueError('Invalid PatchMon port')
    return raw.rstrip('/')

def status(url):
    if not url:return {'ok':True,'configured':False}
    try:
        endpoint=validate(url)
        opener=build_opener(NoRedirect())
        with opener.open(Request(endpoint+'/',headers={'User-Agent':'NetSec-PatchMon-Check/1.0'}),timeout=2.5) as response:
            code=response.status
        return {'ok':True,'configured':True,'url':endpoint,'status':'up' if code<500 else 'down','http_code':code}
    except HTTPError as err:
        code=err.code
        return {'ok':True,'configured':True,'url':url,'status':'up' if code in (301,302,303,307,308,401,403) else 'down','http_code':code}
    except (OSError,URLError,ValueError,TimeoutError) as err:
        return {'ok':True,'configured':True,'status':'down','error_type':type(err).__name__}
