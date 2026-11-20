#!/usr/bin/env python3
"""NetSec AI reliability primitives. No sockets, no command execution.

Failed inferences never replace the last successful advisory. The latest attempt
is kept separately; successful results are also retained in NetSec's SQLite log.
"""
import datetime as dt
import json
import os
import sqlite3
import tempfile
from pathlib import Path

STATE_DIR = Path('/var/lib/server-status/ai')
LAST_ATTEMPT = STATE_DIR / 'last-attempt.json'
JOURNAL = Path('/var/lib/server-status/intel/history.sqlite3')
UTC = dt.timezone.utc


def _write(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.netsec-', suffix='.json', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _read(path):
    try:
        if path.stat().st_size > 45000:
            return None
        obj = json.loads(path.read_text(encoding='utf-8'))
        return obj if isinstance(obj, dict) else None
    except (OSError, ValueError, TypeError):
        return None


def recover_success():
    """Recover a previous successful full report when latest.json was erased by v3.

    Only read persisted data; do not fabricate a current verdict. The original
    timestamp remains, and the dashboard independently marks old data STALE.
    """
    current = _read(STATE_DIR / 'latest.json')
    if current and current.get('state') == 'ready':
        return True
    if not JOURNAL.is_file():
        return False
    try:
        # Read-only SQLite URI avoids creating or migrating the journal here.
        db = sqlite3.connect(f'file:{JOURNAL}?mode=ro', uri=True, timeout=3)
        try:
            rows = db.execute(
                'SELECT payload FROM assessments ORDER BY generated_at DESC LIMIT 8'
            ).fetchall()
        finally:
            db.close()
        for (raw,) in rows:
            try:
                obj = json.loads(raw)
            except (TypeError, ValueError):
                continue
            if (isinstance(obj, dict) and obj.get('state') == 'ready'
                    and obj.get('updated_at') and obj.get('summary')):
                _write(STATE_DIR / 'latest.json', obj)
                return True
    except (sqlite3.Error, OSError):
        pass
    return False


def succeeded(report):
    _write(LAST_ATTEMPT, {
        'state': 'ready', 'at': dt.datetime.now(UTC).isoformat(),
        'summary': 'Jimmy completed an assessment',
        'severity': report.get('severity', 'unknown'),
    })


def failed(message, at=None):
    # Never replace the last successful assessment with an error.
    _write(LAST_ATTEMPT, {
        'state': 'error', 'at': dt.datetime.now(UTC).isoformat(),
        'started_at': at,
        'error': str(message)[:220],
        'summary': 'The most recent AI attempt failed; previous findings are historical.',
    })
    recover_success()
