"""Opt-in host policy regression tests; no host Nginx, systemctl or apt calls."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[1]/'scripts'/'netsec-host-geo-guard.py'
spec=importlib.util.spec_from_file_location('netsec_host_geo_guard',SOURCE)
guard=importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

LEGACY='''# NetSec Canada-only HTTPS policy; DB-IP Lite CC BY 4.0
geoip2 /var/lib/netsec-geoip/dbip-country-lite.mmdb {
 auto_reload 60m;
 $netsec_country_code default=ZZ source=$remote_addr country iso_code;
}
geo $netsec_local_client {
 default 0;
 192.168.0.0/16 1;
}
map "$netsec_local_client:$netsec_country_code" $netsec_ca_denied {
    default 1;
    "0:CA" 0;
    ~^1: 0;
}
'''

class HostGeoGuard(unittest.TestCase):
    def test_default_allowlist_and_ipv6_local_exception(self):
        config=guard.geo_config(('CA','US'))
        self.assertIn('"0:CA" 0;',config)
        self.assertIn('"0:US" 0;',config)
        self.assertIn('fc00::/7 1;',config)
        self.assertIn('fe80::/10 1;',config)
        self.assertIn('source=$remote_addr',config)
        self.assertNotIn('X-Forwarded-For',config)

    def test_migrates_legacy_canada_only(self):
        updated=guard.replace_map(LEGACY,('CA','US'))
        self.assertIn('"0:CA" 0;',updated)
        self.assertIn('"0:US" 0;',updated)
        self.assertEqual(updated.count('map "$netsec_local_client:'),1)
        self.assertEqual(guard.replace_map(updated,('CA','US')),updated)

    def test_rejects_unknown_mappings(self):
        for source in ('', 'map $foo $bar { default 1; }', LEGACY+LEGACY):
            with self.subTest(source=source[:20]):
                with self.assertRaises(ValueError):guard.replace_map(source,('CA','US'))

    def test_country_codes_are_validated(self):
        self.assertEqual(guard.countries('ca,us,ca'),('CA','US'))
        for bad in ('','CA,US,../../etc/passwd','Canada','CA,ZZZ'):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):guard.countries(bad)

    def test_inserts_https_only_without_duplication(self):
        text='''server { listen 80; server_name example.com; }
server { listen 443 ssl; location / { return 200; } }
'''
        updated,count=guard.transform(text)
        self.assertEqual(count,1)
        self.assertEqual(updated.count(guard.MARKER),1)
        again,n=guard.transform(updated)
        self.assertEqual(n,0)
        self.assertEqual(again,updated)

    def test_safe_legacy_migration_preserves_manifest_and_writes_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            conf=root/'geo.conf'
            conf.write_text(LEGACY)
            (root/'active.json').write_text('{"files":[],"geo_conf":"legacy"}')
            commands=[]
            def mocked_call(*args,**kwargs):
                commands.append(args)
                class Result:returncode=1
                return Result()
            def mocked_timer(unit,command):
                self.assertEqual(unit,'netsec-geo-policy-rollback')
                self.assertEqual(command,'rollback-policy')
            with patch.object(guard,'ROOT',root),patch.object(guard,'CONF',conf),\
                 patch.object(guard,'host_only'),patch.object(guard,'call',side_effect=mocked_call),\
                 patch.object(guard,'schedule_timer',side_effect=mocked_timer):
                guard.set_countries(('CA','US'))
                self.assertTrue((root/'policy-pending.json').exists())
                self.assertTrue((root/'active.json').exists())
                self.assertEqual(guard.current_countries(),('CA','US'))
                self.assertIn(('nginx','-t'),commands)
                guard.rollback_policy()
                self.assertEqual(guard.current_countries(),('CA',))
                self.assertFalse((root/'policy-pending.json').exists())

    def test_no_automatic_host_mutations_in_container_installer(self):
        script=(SOURCE.parents[0]/'install-lxc.sh').read_text()
        self.assertNotIn('netsec-host-geo-guard.py enable',script)
        self.assertNotIn('netsec-host-geo-guard.py set-countries',script)

if __name__=='__main__':unittest.main()
