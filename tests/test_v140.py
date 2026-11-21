"""Jimmy v1.4 action plan and private PatchMon reachability guardrails."""
import pathlib
import sys
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
import netsec_patchmon as PM

class V14(unittest.TestCase):
    def test_private_ip_is_required(self):
        self.assertEqual(PM.validate('http://192.168.2.125:3000'),'http://192.168.2.125:3000')
        for url in ('https://example.org','http://127.0.0.1:3000','http://169.254.1.1',
                    'http://192.168.2.125:3000/admin','http://user:secret@192.168.2.125:3000',
                    'http://192.168.2.125:3000?key=abc','ftp://192.168.2.125',
                    'http://0.0.0.0:3000'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                PM.validate(url)
    def test_unconfigured_is_safe(self):
        self.assertEqual(PM.status(None),{'ok':True,'configured':False})
    def test_auth_redirect_is_reachable_without_following(self):
        with patch.object(PM,'build_opener') as opener:
            opener.return_value.open.side_effect=HTTPError(
               'http://192.168.2.125:3000',302,'Redirect',{},None)
            result=PM.status('http://192.168.2.125:3000')
        self.assertEqual(result['status'],'up')
    def test_no_automatic_action_execution(self):
        html=(ROOT/'app/index.html').read_text()
        js=(ROOT/'app/jimmy-action-plan.js').read_text()
        app=(ROOT/'app/app.py').read_text()
        self.assertIn('jimmyActionList',html)
        self.assertIn('jimmyPatchmonStatus',html)
        self.assertIn('window.netsecJimmyActionPlan',js)
        self.assertIn('/api/integrations/patchmon',app)
        self.assertNotIn('eval(',js)
        self.assertNotIn('innerHTML',js)
        self.assertNotIn('subprocess', (ROOT/'app/netsec_patchmon.py').read_text())
    def test_updater_targets_configured_listener(self):
        updater=(ROOT/'scripts/netsec-auto-update').read_text()
        self.assertIn("opts.get('bind')",updater)
        self.assertIn('for attempt in range(12)',updater)

if __name__=='__main__':unittest.main()
