#!/usr/bin/env python3
"""Import only the local homepage's service status file; no HTTP requests.

Expected format: {"checked_at": ISO8601 UTC, "services": {key: {"ok":bool,"http":int|null}}}.
The source is a read-only bind mount of the public homepage status folder.
"""
from datetime import datetime, timezone
from pathlib import Path
import json
import math
import threading
import time

# Latest valid homepage snapshot, retained only for a short outage.
_LAST_GOOD = {}
_CACHE_LOCK = threading.Lock()
LAST_GOOD_MAX_AGE_SECONDS = 3600

DISPLAY_NAMES = {
    'pve':'Proxmox VE', 'netsec':'NetSec', 'ai':'Open WebUI',
    'searxng':'SearXNG', 'plex':'Plex', 'nzbget':'NZBGet',
    'prowlarr':'Prowlarr', 'radarr':'Radarr', 'sonarr':'Sonarr',
    'transmission':'Transmission'
}
MAX_BYTES = 131072


def parse_time(value):
    if not isinstance(value, str):
        raise ValueError('checked_at is not a timestamp')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def feed(path, max_age_seconds=150):
    """Return a stable status/metadata structure even if file is missing/stale."""
    result = {'source':'Local infrastructure homepage (local file)',
              'state':'unavailable','checked_at':None,'age_seconds':None,
              'services':[], 'error':None}
    if not path:
        result['state']='not_configured'
        return result
    key = str(path)
    try:
        path = Path(path)
        if not path.is_file():
            raise OSError('status.json not found in read-only mount')
        with path.open('rb') as f:
            raw = f.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError('status.json exceeds 128 KiB limit')
        document = json.loads(raw)
        if not isinstance(document,dict) or not isinstance(document.get('services'),dict):
            raise ValueError('Invalid homepage status schema')
        checked_at = parse_time(document.get('checked_at'))
        age = (datetime.now(timezone.utc)-checked_at).total_seconds()
        max_age = max(30,min(int(max_age_seconds),3600))
        fresh = -60 <= age <= max_age
        result.update(state='fresh' if fresh else 'stale',
                      checked_at=checked_at.isoformat(),
                      age_seconds=round(age))
        entries=document['services']
        for key, raw_service in list(entries.items())[:25]:
            if not isinstance(raw_service,dict):
                raw_service={}
            good=raw_service.get('ok')
            code=raw_service.get('http')
            if isinstance(code,bool) or not isinstance(code,int) or code<100 or code>599:
                code=None
            if not fresh:
                status='stale'
            elif good is True:
                status='up'
            elif good is False:
                status='down'
            else:
                status='unknown'
            result['services'].append({'id':str(key)[:40],
                                       'name':DISPLAY_NAMES.get(str(key),str(key).replace('_',' ').title())[:75],
                                       'status':status,
                                       'http_code':code,
                                       'source':'homepage',
                                       'checked_at':result['checked_at']})
        if not result['services']:
            raise ValueError('No services found in homepage status feed')
        # Keep a bounded, in-memory snapshot so a partially written JSON file
        # does not make the entire list disappear on the next dashboard refresh.
        # Never treat this fallback as a live reachability result.
        if fresh:
            with _CACHE_LOCK:
                _LAST_GOOD.clear()
                _LAST_GOOD[key] = (time.monotonic(), result['checked_at'],
                                   [dict(item) for item in result['services']])
    except (OSError, ValueError, TypeError, OverflowError) as exc:
        result.update(state='unavailable',checked_at=None,age_seconds=None,
                      services=[],error=type(exc).__name__ + ': ' + str(exc)[:130])
        with _CACHE_LOCK:
            previous = _LAST_GOOD.get(key)
        if previous and 0 <= time.monotonic() - previous[0] <= LAST_GOOD_MAX_AGE_SECONDS:
            result.update(state='stale',checked_at=previous[1],
                          age_seconds=round(time.monotonic()-previous[0]),
                          services=[dict(item,status='stale') for item in previous[2]],
                          error=result['error']+'; displaying last known services, NOT live status')
    return result


def select_services(homepage, service_monitor):
    """Prefer fresh homepage data, configured direct checks, then stale context.

    If an operator configured a homepage feed but it is unavailable, preserve
    that source state so the UI does not inaccurately say 'not configured'.
    """
    monitoring = service_monitor if isinstance(service_monitor, dict) else {}
    direct = monitoring.get('services') or []
    feed = homepage if isinstance(homepage, dict) else None
    if feed and feed.get('state') == 'fresh' and feed.get('services'):
        return feed['services'], 'homepage'
    if direct:
        return direct, 'configured'
    if feed:
        return feed.get('services') or [], 'homepage'
    return [], 'configured'
