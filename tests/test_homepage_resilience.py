"""Regression tests for transient Homepage feed failures and source-selection logic."""
import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
import netsec_homepage as H

class HomepageResilience(unittest.TestCase):
    def setUp(self):
        with H._CACHE_LOCK:
            H._LAST_GOOD.clear()

    def healthy(self, path):
        payload={'checked_at':dt.datetime.now(dt.timezone.utc).isoformat(),
                 'services':{'pve':{'ok':True,'http':200},
                             'netsec':{'ok':True,'http':401},
                             'transmission':{'ok':True,'http':401}}}
        Path(path).write_text(json.dumps(payload))

    def test_valid_homepage_preserves_auth_required_services(self):
        with tempfile.TemporaryDirectory() as temp:
            file=Path(temp)/'status.json'
            self.healthy(file)
            result=H.feed(str(file))
            self.assertEqual(result['state'],'fresh')
            self.assertEqual(len(result['services']),3)
            self.assertTrue(all(x['status']=='up' for x in result['services']))
            self.assertEqual(result['services'][1]['http_code'],401)

    def test_transient_malformed_json_shows_stale_not_zero(self):
        with tempfile.TemporaryDirectory() as temp:
            file=Path(temp)/'status.json'
            self.healthy(file)
            first=H.feed(str(file))
            file.write_text('{"checked_at":')
            result=H.feed(str(file))
            self.assertEqual(result['state'],'stale')
            self.assertEqual(len(result['services']),len(first['services']))
            self.assertTrue(all(x['status']=='stale' for x in result['services']))
            self.assertIn('NOT live',result['error'])

    def test_missing_file_after_good_read_is_stale(self):
        with tempfile.TemporaryDirectory() as temp:
            file=Path(temp)/'status.json'
            self.healthy(file)
            H.feed(str(file))
            file.unlink()
            result=H.feed(str(file))
            self.assertEqual(result['state'],'stale')
            self.assertEqual(len(result['services']),3)

    def test_never_reuses_stale_for_other_status_source(self):
        with tempfile.TemporaryDirectory() as temp:
            file=Path(temp)/'status.json'
            self.healthy(file)
            H.feed(str(file))
            other=H.feed(str(Path(temp)/'other.json'))
            self.assertEqual(other['state'],'unavailable')
            self.assertEqual(other['services'],[])

    def test_source_select_reports_unavailable_homepage_instead_of_no_config(self):
        feed={'state':'unavailable','services':[],'error':'missing'}
        records,source=H.select_services(feed,{'state':'not_configured','services':[]})
        self.assertEqual((records,source),([], 'homepage'))

    def test_explicit_direct_checks_override_stale_homepage(self):
        feed={'state':'stale','services':[{'status':'stale','name':'Old'}]}
        direct={'state':'checked','services':[{'name':'New','status':'up'}]}
        rows,source=H.select_services(feed,direct)
        self.assertEqual(source,'configured')
        self.assertEqual(rows[0]['name'],'New')

    def test_stale_homepage_without_direct_checks_is_visible_as_stale(self):
        feed={'state':'stale','services':[{'status':'stale','name':'Old'}]}
        rows,source=H.select_services(feed,{'services':[]})
        self.assertEqual(source,'homepage')
        self.assertEqual(rows[0]['status'],'stale')

    def test_dashboard_does_not_call_unavailable_not_configured(self):
        ui=(ROOT/'app/index.html').read_text()
        self.assertIn("state==='unavailable'?'FEED ERROR'",ui)
        self.assertIn("Showing last-known Homepage entries ONLY.",ui)
        self.assertIn('Homepage status feed unavailable.',ui)
        app=(ROOT/'app/app.py').read_text()
        self.assertIn("KVG.select_services(homepage, service_monitor)",app)

if __name__=='__main__':unittest.main()
