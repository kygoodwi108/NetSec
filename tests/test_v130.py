"""NetSec v1.3: deterministic security findings and bounded request explorer."""
import datetime as dt
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
import netsec_request_explorer as RX
import netsec_findings as NF

class V13(unittest.TestCase):
    def test_request_explorer_sanitizes_and_filters(self):
        now=dt.datetime.now(dt.timezone.utc)
        records=[
          {'ip':'203.0.113.7','when':now-dt.timedelta(minutes=10),'method':'GET','path':'/.env','status':403,'bytes':90,'probe_like':True},
          {'ip':'203.0.113.7','when':now-dt.timedelta(minutes=5),'method':'GET','path':'/login','status':200,'bytes':124,'probe_like':False},
          {'ip':'203.0.113.8','when':now,'method':'GET','path':'/other','status':200,'bytes':10,'probe_like':False}]
        result=RX.explore(lambda:['/tmp/mock.log'],lambda p:['x','y','z'],lambda raw:records['xyz'.index(raw)],
                          '203.0.113.7')
        self.assertTrue(result['ok'])
        self.assertEqual(result['matching_records'],2)
        self.assertEqual(result['records'][0]['path'],'/login')
        self.assertNotIn('query',result['records'][0])
        self.assertEqual(len(RX.explore(lambda:['/tmp/mock.log'],lambda p:['x','y','z'],
          lambda raw:records['xyz'.index(raw)],'203.0.113.7',status='4xx')['records']),1)
    def test_explorer_rejects_unsafe_pagination(self):
        with self.assertRaises(ValueError):
            RX.explore(lambda:[],lambda p:[],lambda raw:None,'example.com')
        with self.assertRaises(ValueError):
            RX.explore(lambda:[],lambda p:[],lambda raw:None,'127.0.0.1',limit=999)
    def test_findings_are_dynamic_not_three_fixed_cards(self):
        self.assertEqual(NF.build({},{}),[])
        e={'service_health':{'fresh':True,'down':1},'sampled_backend_errors':0,
           'sampled_crowdsec_timer_errors':0,'http_5xx_aggregate':0,'requests_aggregate':100}
        findings=NF.build(e,{})
        self.assertEqual([x['id'] for x in findings],['services-down'])
        self.assertEqual(findings[0]['category'],'infrastructure')
        self.assertNotIn('compromise',findings[0]['title'].lower())
    def test_ui_combines_source_tabs(self):
        html=(ROOT/'app/index.html').read_text()
        self.assertIn('initConnections(tabs.intel)',html)
        self.assertNotIn('initConnections(tabs.connections)',html)
        self.assertIn('netsec-v13.js',html)
        js=(ROOT/'app/netsec-v13.js').read_text()
        for token in ('/api/source-requests','/api/intel/label','/api/ban','Ask Jimmy about this IP'):
            self.assertIn(token,js)
        self.assertNotIn('innerHTML',js)

if __name__=='__main__':unittest.main()
