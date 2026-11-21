#!/usr/bin/env python3
"""Authenticated manual refresh and live AI run status for NetSec.

The dashboard NEVER executes shell commands. It creates a single well-known
marker file. A root-owned systemd path/service pair starts the existing analyst.
"""
import datetime as dt
import json
import os
import threading
import time
from pathlib import Path

import netsec_intel as NI
import netsec_proxy_auth as NPA
import netsec_ai_resilience as AR

BASE = Path('/var/lib/server-status/ai')
REQUEST = BASE / 'refresh.request'
RUNNING = BASE / 'refresh.running'
LAST_REQUEST = BASE / 'refresh-last-request.json'
MIN_GAP_SEC = 60
BUSY_MAX_SEC = 900
_LOCK = threading.Lock()


def _read_json(path, max_bytes=60000):
    try:
        if path.stat().st_size > max_bytes:
            return None
        d = json.loads(path.read_text(encoding='utf-8'))
        return d if isinstance(d, dict) else None
    except (OSError, TypeError, ValueError):
        return None


def _stamped_epoch(s):
    try:
        t = dt.datetime.fromisoformat(str(s).replace('Z', '+00:00'))
        if t.tzinfo is None:
            return 0
        return t.timestamp()
    except (ValueError, TypeError):
        return 0


def run_status():
    now = time.time()
    states = {}
    for f in (REQUEST, RUNNING):
        try:
            age = now - f.stat().st_mtime
            states[f.name] = age < BUSY_MAX_SEC
        except OSError:
            states[f.name] = False
    latest = _read_json(BASE / 'latest.json') or {}
    attempt = _read_json(AR.LAST_ATTEMPT) or {}
    # No API key or sensitive internal filenames exposed.
    return {
        'busy': states['refresh.request'] or states['refresh.running'],
        'queued': states['refresh.request'],
        'running': states['refresh.running'],
        'last_attempt': {k: attempt.get(k) for k in ('state','at','summary','error') if k in attempt},
        'latest_ready_at': latest.get('updated_at') if latest.get('state') == 'ready' else None,
    }


def ai_report():
    """Serve the last valid report, clearly marked stale, plus latest attempt."""
    d = _read_json(BASE / 'latest.json')
    if not d or d.get('state') != 'ready':
        if AR.recover_success():
            d = _read_json(BASE / 'latest.json')
    attempt = _read_json(AR.LAST_ATTEMPT) or {}
    if not d or d.get('state') != 'ready':
        return {
            'state': 'not_configured', 'severity': 'unknown',
            'summary': 'No successful AI assessment is available yet.',
            'last_attempt': {k: attempt.get(k) for k in ('state','at','error') if k in attempt},
        }
    age = time.time() - _stamped_epoch(d.get('updated_at'))
    state = 'ready' if 0 <= age <= 35 * 60 else 'stale'
    severity = d.get('severity', 'unknown')
    if severity not in ('green','amber','red','unknown'):
        severity = 'unknown'
    data = {
        'state': state,
        'severity': severity,
        'summary': str(d.get('summary') or '')[:450],
        'updated_at': d.get('updated_at'),
        'model': str(d.get('model') or '')[:65],
        'confidence': d.get('confidence') if d.get('confidence') in ('low','medium','high') else 'low',
        'observations': [str(x)[:260] for x in (d.get('observations') or [])[:4] if isinstance(x,str)],
        'recommended_actions': [str(x)[:300] for x in (d.get('recommended_actions') or [])[:3] if isinstance(x,str)],
        'last_attempt': {k: attempt.get(k) for k in ('state','at','error') if k in attempt},
        'verification_results':{
            'generated_at':(d.get('verification_results') or {}).get('generated_at'),
            'checks':(d.get('verification_results') or {}).get('checks',[])[:3],
            'sensitive_path_details':(d.get('verification_results') or {}).get('sensitive_path_details',[])[:12],
        },
        'warning': 'AI is advisory only; stale assessments are not current security findings.',
    }
    data['evidence_review'] = d.get('evidence_review') or {}
    data['suppressed_duplicate_actions'] = int(d.get('suppressed_duplicate_actions') or 0)
    data['risk_assessment'] = d.get('risk_assessment') or {}
    data['findings'] = (d.get('findings') or [])[:8]
    data['model_response'] = d.get('model_response') or {}
    data['operator_feedback_context'] = d.get('operator_feedback_context') or {}
    return data


def _send_json(handler, status, obj):
    body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
    handler.send_response(status)
    for k, v in (
        ('Content-Type', 'application/json; charset=utf-8'),
        ('Content-Length', str(len(body))),
        ('Cache-Control', 'no-store'),
        ('X-Content-Type-Options', 'nosniff'),
        ('Referrer-Policy', 'no-referrer'),
    ):
        handler.send_header(k,v)
    handler.end_headers()
    handler.wfile.write(body)


def get_status(handler):
    _send_json(handler, 200, {'ok': True, **run_status(), 'ai': ai_report()})


def do_trigger(handler):
    if not NPA.require(handler,write=True): return
    # Do not accept a body or user-supplied command, path, script, or service name.
    try:
        content_length = int(handler.headers.get('Content-Length','0'))
    except ValueError:
        content_length = -1
    if content_length != 0:
        return _send_json(handler,400,{'ok':False,'error':'Refresh requests must have no body'})
    with _LOCK:
        status = run_status()
        if status['busy']:
            return _send_json(handler,409,{'ok':False,'error':'Jimmy analysis is already queued or running'})
        prev = _read_json(LAST_REQUEST) or {}
        since = time.time() - _stamped_epoch(prev.get('at'))
        if 0 <= since < MIN_GAP_SEC:
            return _send_json(handler,429,{
                'ok':False, 'error': f'Please allow {int(MIN_GAP_SEC-since)+1} seconds between manual refreshes'
            })
        BASE.mkdir(parents=True, exist_ok=True, mode=0o750)
        at = dt.datetime.now(dt.timezone.utc).isoformat()
        try:
            # O_EXCL prevents duplicate marker replacement; systemd consumes this file.
            fd = os.open(REQUEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os,'O_NOFOLLOW',0), 0o600)
            try:
                os.write(fd, (at+'\n').encode('ascii'))
            finally:
                os.close(fd)
        except FileExistsError:
            return _send_json(handler,409,{'ok':False,'error':'A refresh is already queued'})
        except OSError:
            return _send_json(handler,500,{'ok':False,'error':'Cannot queue analysis; check dashboard permissions'})
        try:
            AR._write(LAST_REQUEST,{'at':at})
        except OSError:
            # Request marker is already sufficient; don't claim the request failed.
            pass
    _send_json(handler,202,{'ok':True,'state':'queued','queued_at':at,
                            'message':'Jimmy refresh queued; review running status shortly'})
