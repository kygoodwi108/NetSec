#!/usr/bin/env python3
"""Download free DB-IP Country Lite CSV and build an offline SQLite country index.

Third-party IP data stays on this machine. Source: https://db-ip.com/db/lite.php
Licensed CC BY 4.0; attribution displayed in the NetSec dashboard.
"""
import csv
import datetime
import gzip
import ipaddress
import os
import sqlite3
import sys
import tempfile
import urllib.request
from pathlib import Path

DEST = Path(os.environ.get('NETSEC_GEOIP_PATH','/var/lib/server-status/geoip-country.sqlite3'))
MONTH = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m')
MONTH = sys.argv[1] if len(sys.argv) > 1 else MONTH
if len(MONTH) != 7 or MONTH[4] != '-' or not MONTH[:4].isdigit() or not MONTH[5:].isdigit() or not 1 <= int(MONTH[5:]) <= 12:
    raise SystemExit('Usage: python3 geoip_update.py [YYYY-MM]')
URL = f'https://download.db-ip.com/free/dbip-country-lite-{MONTH}.csv.gz'
print('Downloading DB-IP Country Lite:', URL, flush=True)
DEST.parent.mkdir(parents=True,exist_ok=True)
with tempfile.TemporaryDirectory(prefix='netsec-geoip-',dir=str(DEST.parent)) as tmp:
    path = Path(tmp) / 'dbip-country.csv.gz'
    req = urllib.request.Request(URL, headers={'User-Agent': 'NetSecOfflineGeoIP/2.0'})
    with urllib.request.urlopen(req, timeout=60) as response, open(path, 'wb') as f:
        size = 0
        while True:
            chunk = response.read(262144)
            if not chunk:
                break
            size += len(chunk)
            if size > 40_000_000:
                raise RuntimeError('Unexpectedly large compressed country database')
            f.write(chunk)
    dbtmp = Path(tmp) / 'country.sqlite3'
    conn = sqlite3.connect(dbtmp)
    conn.executescript('''
        PRAGMA journal_mode=OFF;
        PRAGMA synchronous=OFF;
        CREATE TABLE ip_ranges (family INTEGER NOT NULL, start_ip BLOB NOT NULL, end_ip BLOB NOT NULL, country TEXT NOT NULL);
    ''')
    batch = []
    count = 0
    with gzip.open(path, 'rt', encoding='utf8', newline='') as stream:
        for row in csv.reader(stream):
            if len(row) < 3:
                continue
            try:
                start, end = ipaddress.ip_address(row[0]), ipaddress.ip_address(row[1])
                country = row[2].upper()
                if start.version != end.version or not (len(country) == 2 and country.isalpha()):
                    continue
            except ValueError:
                continue
            batch.append((start.version, start.packed.rjust(16, b'\0'), end.packed.rjust(16, b'\0'), country))
            if len(batch) >= 15000:
                conn.executemany('INSERT INTO ip_ranges VALUES (?,?,?,?)', batch)
                count += len(batch)
                batch.clear()
    if batch:
        conn.executemany('INSERT INTO ip_ranges VALUES (?,?,?,?)', batch)
        count += len(batch)
    if count < 100000:
        raise RuntimeError(f'Refusing incomplete country database ({count} rows)')
    conn.execute('CREATE INDEX by_ip ON ip_ranges(family, start_ip)')
    conn.commit()
    conn.close()
    os.chmod(dbtmp, 0o644)
    os.replace(dbtmp, DEST)
print(f'Installed {count:,} offline country ranges at {DEST}', flush=True)
print('Restart dashboard: systemctl restart server-status', flush=True)
