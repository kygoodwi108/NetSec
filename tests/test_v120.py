"""NetSec v1.2: fail-closed automatic update and Jimmy continuity tests."""
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
UPDATE=runpy.run_path(str(ROOT/'scripts/netsec-auto-update'))
import netsec_jimmy_store as STORE

class AutoUpdate(unittest.TestCase):
    def test_versions_only_stable_v1(self):
        parse=UPDATE['parse_version']
        self.assertEqual(parse('v1.2.3'),(1,2,3))
        for value in ('v2.0.0','v1.2.3-rc1','latest','v1.2',''):
            self.assertIsNone(parse(value))
    def test_require_digest_and_fixed_owner(self):
        get=UPDATE['get_asset']
        tag='v1.2.1'
        name='netsec-'+tag+'-source.zip'
        url='https://github.com/kygoodwi108/NetSec/releases/download/'+tag+'/'+name
        good={'tag_name':tag,'draft':False,'prerelease':False,
              'assets':[{'name':name,'browser_download_url':url,'digest':'sha256:'+'a'*64}]}
        self.assertEqual(get(good),((1,2,1),url,'a'*64))
        with self.assertRaises(RuntimeError):
            get({**good,'assets':[{**good['assets'][0],'digest':None}]})
        with self.assertRaises(RuntimeError):
            get({**good,'assets':[{**good['assets'][0],'browser_download_url':'https://evil.example/patch.zip'}]})
        with self.assertRaises(RuntimeError):
            get({**good,'prerelease':True})
    def test_history_survives_assessment_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(STORE,'DB',Path(tmp)/'jimmy.sqlite3'):
                first=STORE.save_report({'updated_at':'2026-11-19T10:00:00Z','summary':'Prior report'})
                second=STORE.save_report({'updated_at':'2026-11-20T10:00:00Z','summary':'New report'})
                STORE.add_exchange(first,'What happened?','One earlier service failure.')
                STORE.add_exchange(second,'Has it changed?','Cannot conclude without comparison.')
                self.assertEqual(len(STORE.recent_messages()),4)
                self.assertEqual(STORE.recent_messages()[0]['content'],'What happened?')
                self.assertEqual(len(STORE.recent_reports()),2)

if __name__=='__main__':unittest.main()
