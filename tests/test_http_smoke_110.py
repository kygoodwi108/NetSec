"""End-to-end smoke of built-in HTTP server with synthetic local-only config."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request,urlopen

ROOT=Path(__file__).resolve().parents[1]

class HttpSmoke(unittest.TestCase):
    def test_local_server_routes_and_auth(self):
        with tempfile.TemporaryDirectory() as td:
            with socket.socket() as sock:
                sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            cfg=Path(td)/'config.json'
            cfg.write_text(json.dumps({'bind':'127.0.0.1','port':port,'access_log_globs':[],
                            'services':[],'crowdsec_alerts_json':'','geoip_db':str(Path(td)/'absent.sqlite')}))
            proc=subprocess.Popen([sys.executable,'-B',str(ROOT/'app/app.py')],
                   env={**os.environ,'STATUS_CONFIG':str(cfg)},stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE)
            try:
                base='http://127.0.0.1:'+str(port)
                for i in range(70):
                    try:
                        with urlopen(base+'/manifest.webmanifest',timeout=1) as r:
                            self.assertEqual(json.loads(r.read())['display'],'standalone')
                        break
                    except OSError:time.sleep(.07)
                else:self.fail('Server did not become ready')
                for path in ('/','/sw.js','/jimmy-ui.js','/offline.html','/icon-192.png','/icon-512.png'):
                    with urlopen(base+path,timeout=5) as r:self.assertEqual(r.status,200,path)
                with urlopen(base+'/api/status',timeout=10) as r:
                    body=json.load(r)
                    self.assertEqual(body['service_monitor']['state'],'not_configured')
                for path in ('/api/jimmy/workspace','/api/push/status'):
                    with self.assertRaises(HTTPError) as exc:urlopen(base+path,timeout=5)
                    self.assertEqual(exc.exception.code,403)
                req=Request(base+'/api/jimmy/feedback',method='POST',data=b'{}',headers={
                    'Content-Type':'application/json','X-NetSec-Action':'dashboard'})
                with self.assertRaises(HTTPError) as exc:urlopen(req,timeout=5)
                self.assertEqual(exc.exception.code,403)
            finally:
                proc.terminate()
                try:proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:proc.kill();proc.communicate()
