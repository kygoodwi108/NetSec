"""Offline regression tests for NetSec v1.1.0 consolidated source."""
import ast
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
from email.message import Message
from io import BytesIO

ROOT=pathlib.Path(__file__).resolve().parents[1]
APP=ROOT/'app'
sys.path.insert(0,str(APP))

class Handler:
    def __init__(self,ip='192.0.2.10',user='netsecadmin',origin='https://netsec.example.org',host='netsec.example.org',action='dashboard',site='same-origin'):
        self.client_address=(ip,45231)
        self.headers=Message()
        for k,v in [('X-NetSec-Authenticated-User',user),('X-NetSec-Action',action),('Origin',origin),('Host',host),('Sec-Fetch-Site',site)]:
            if v is not None:self.headers.add_header(k,v)
        self.status=None;self.wfile=BytesIO()
    def send_response(self,s):self.status=s
    def send_header(self,k,v):pass
    def end_headers(self):pass

class Release(unittest.TestCase):
    def test_syntax_all(self):
        for p in APP.glob('*.py'):ast.parse(p.read_text(),filename=str(p))
    def test_no_embedded_site_domain(self):
        for p in APP.iterdir():
            if p.suffix in ('.py','.html'):
                self.assertNotIn('kvgoodwin.com',p.read_text())
    def test_full_sources(self):
        for name in ('app.py','netsec_ai.py','netsec_jimmy_checks.py','netsec_risk_v384.py','netsec_source_hub.py','netsec_source_ai.py','netsec_proxy_auth.py','index.html','netsec_ban_worker.py'):
            self.assertTrue((APP/name).is_file(),name)
    def test_proxy_auth(self):
        import netsec_proxy_auth as a
        with tempfile.TemporaryDirectory() as td:
            saved=a.CONFIG
            a.CONFIG=pathlib.Path(td)/'auth.json'
            try:
                self.assertFalse(a.require(Handler(),write=True))
                a.CONFIG.write_text(json.dumps({'trusted_proxy_ip':'192.0.2.10','username':'netsecadmin','origin':'https://netsec.example.org'}))
                self.assertTrue(a.require(Handler(),write=True))
                self.assertFalse(a.require(Handler(ip='192.0.2.11'),write=True))
                self.assertFalse(a.require(Handler(user='someoneelse'),write=True))
                self.assertFalse(a.require(Handler(action=None),write=True))
                self.assertFalse(a.require(Handler(site='cross-site'),write=True))
                self.assertFalse(a.require(Handler(host='other.example'),write=True))
                self.assertFalse(a.require(Handler(origin='https://evil.example'),write=True))
            finally:a.CONFIG=saved
    def test_sensitivity_limits(self):
        import netsec_jimmy_checks as j
        with tempfile.TemporaryDirectory() as td:
            settings=pathlib.Path(td)/'sample.json'
            settings.write_text(json.dumps({'nginx_host_ip':'192.168.1.10','https_hosts':['netsec.example.org'],'sensitive_probe_mode':'rotating','sensitive_probe_source_allowlisted':False}))
            self.assertEqual(j.settings(settings)['sensitive_probe_mode'],'rotating')
    def test_no_automatic_bans_from_ai(self):
        s=(APP/'netsec_source_ai.py').read_text()
        self.assertNotIn('netsec_ban_worker',s)
        self.assertNotIn('cscli decisions add',s)
    def test_roadmap_retains_safety_boundaries(self):
        txt=(ROOT/'docs'/'ROADMAP.md').read_text()
        self.assertIn('no autonomous bans',txt.lower()) if 'no autonomous bans' in txt.lower() else self.assertIn('no command execution',txt.lower())

if __name__=='__main__':unittest.main()
