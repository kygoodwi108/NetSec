"""Portable service monitor checks and installation regressions."""
import os
import pathlib
import socket
import sys
import unittest
from unittest.mock import patch

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
import netsec_service_checks as checks

class GenericChecks(unittest.TestCase):
    def test_validate_http_tcp(self):
        self.assertEqual(checks.validate({'name':'Website','url':'https://example.com/health'})['type'],'http')
        self.assertEqual(checks.validate({'name':'PVE','type':'tcp','host':'192.168.2.72','port':8006})['port'],8006)
        for row in ({'name':'No URL','type':'http','url':'file:///etc/shadow'},
                    {'name':'With credentials','url':'https://user:pass@example.com'},
                    {'name':'Wrong TCP port','type':'tcp','host':'localhost','port':65536},
                    {'name':'Bad port','url':'https://example.com:garbage/'}):
            with self.subTest(row=row), self.assertRaises(ValueError):checks.validate(row)

    def test_no_personal_homepage_dependency(self):
        self.assertEqual(checks.sample([])['state'],'not_configured')
        src=(ROOT/'app/app.py').read_text()
        self.assertIn("service_monitor = SVC.sample(CFG.get('services', []))",src)
        self.assertIn("'service_source': service_source",src)
        ui=(ROOT/'app/index.html').read_text()
        self.assertIn('DIRECT CHECKS',ui)
        self.assertIn('No services configured.',ui)

    def test_generic_tcp_port(self):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
        try:
            port=listener.getsockname()[1]
            d=checks.run([{'name':'Test TCP','type':'tcp','host':'127.0.0.1','port':port}])[0]
            self.assertEqual(d['status'],'up')
            self.assertEqual(d['type'],'tcp')
        finally:
            listener.close()

    def test_http_auth_required_is_reachable(self):
        from urllib.error import HTTPError
        with patch.object(checks,'urlopen',side_effect=HTTPError('https://example.org',401,'auth',{},None)):
            d=checks.run([{'name':'Login','url':'https://example.org'}])[0]
            self.assertEqual((d['status'],d['http_code']),('up',401))

    def test_installer_first_boot_and_dependencies(self):
        text=(ROOT/'scripts/proxmox-setup.sh').read_text()
        self.assertIn('umask 0022',text)
        self.assertIn('chmod 755 /etc',text)
        self.assertIn('runuser -u _apt -- getent ahostsv4',text)
        self.assertIn('geoip_update.py',text)
        self.assertIn('SERVICE_CHECKS=()',text)
        self.assertIn('SWITCH-TO-$CTID',text)
        self.assertIn('configure-host-bouncer.sh',text)
        self.assertTrue((ROOT/'systemd/netsec-geoip-update.timer').exists())
        self.assertIn('--cutover', (ROOT/'scripts/configure-host-bouncer.sh').read_text())

if __name__=='__main__': unittest.main()
