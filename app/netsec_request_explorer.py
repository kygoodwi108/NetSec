#!/usr/bin/env python3
"""Authenticated, bounded per-source request explorer.

Only returns sanitized fields from the existing NetSec log reader. It never
exposes URI queries, HTTP headers, request bodies or credentials. A missing
log is reported as missing coverage rather than silently invented history.
"""
import datetime as dt
import ipaddress
import os

MAX_SCAN=300000
MAX_RESULTS=20000
PAGE_SIZE=100
WINDOWS={'1h':1,'24h':24,'7d':168}

def explore(files,lines,parse,ip,window='24h',offset=0,limit=100,status='all',search=''):
    try:
        ip=str(ipaddress.ip_address(ip))
    except (ValueError,TypeError):
        raise ValueError('Invalid single source IP') from None
    if window not in WINDOWS:raise ValueError('Invalid investigation window')
    if status not in ('all','2xx','3xx','4xx','5xx'):raise ValueError('Invalid HTTP status filter')
    if not isinstance(search,str) or len(search)>100:raise ValueError('Invalid path filter')
    try:
        offset=int(offset);limit=int(limit)
    except (TypeError,ValueError):raise ValueError('Invalid pagination') from None
    if offset<0 or offset>MAX_RESULTS or not 1<=limit<=PAGE_SIZE:
        raise ValueError('Pagination out of range')
    now=dt.datetime.now(dt.timezone.utc)
    cutoff=now-dt.timedelta(hours=WINDOWS[window])
    scan=0;matched=0;records=[];errors=[];readable=0;truncated=False
    for filename in files():
        try:
            if not os.path.isfile(filename):continue
            readable+=1
            for raw in lines(filename):
                scan+=1
                if scan>MAX_SCAN:
                    truncated=True;break
                row=parse(raw)
                if not row or row.get('ip')!=ip:continue
                when=row.get('when')
                if when is None or not cutoff<=when<=now+dt.timedelta(minutes=3):continue
                code=int(row.get('status',0))
                if status!='all' and code//100!=int(status[0]):continue
                path=str(row.get('path') or '/')[:190]
                if search and search.lower() not in path.lower():continue
                matched+=1
                if len(records)<MAX_RESULTS:
                    records.append({'at':when.isoformat(),'method':str(row.get('method') or '')[:10],
                        'path':path,'status':code,'bytes':int(row.get('bytes') or 0),
                        'probe_like':bool(row.get('probe_like'))})
                else:
                    truncated=True
            if scan>MAX_SCAN:break
        except (OSError,EOFError,UnicodeError,ValueError) as ex:
            errors.append(os.path.basename(filename)+': '+type(ex).__name__)
    records.sort(key=lambda r:(r['at'],r['path']),reverse=True)
    page=records[offset:offset+limit]
    return {'ok':True,'ip':ip,'window':window,'status':status,'search':search,
            'offset':offset,'limit':limit,'matching_records':matched,
            'records':page,'next_offset':offset+limit if offset+limit<len(records) else None,
            'coverage':{'log_files_readable':readable,'records_scanned':min(scan,MAX_SCAN),
                        'complete':not truncated and not errors,
                        'truncated':truncated,'warnings':errors[:8],
                        'note':'Every available matching request within bounded readable logs; not a guarantee of all historical requests. Queries, cookies and headers are excluded.'}}
