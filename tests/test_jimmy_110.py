"""NetSec 1.1.0: isolated regression tests for chat, feedback, auth, push, and PWA."""
import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
import netsec_jimmy_store as STORE
import netsec_push as PUSH
import netsec_jimmy_api as API
import netsec_proxy_auth as AUTH


def report(at='2026-11-20T19:00:00+00:00',severity='red',reason='Multiple HTTPS services are down and the bounded log sample contains at least 20 real upstream failures'):
    return {'state':'ready','updated_at':at,'model':'qwen3:8b','severity':severity,
        'summary':'Verified significant service outage','observations':['22 genuine upstream failures'],
        'risk_assessment':{'severity':severity,'method':'deterministic cross-check of bounded observations',
                           'reasons':[reason],'sample_counts':{'real_upstream_errors':22}}}

class FakeResponse:
    def __init__(self):
        from io import BytesIO
        self.wfile=BytesIO();self.status=None
    def send_response(self,status):self.status=status
    def send_header(self,k,v):pass
    def end_headers(self):pass

class Jimmy(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.saved_db=STORE.DB
        STORE.DB=Path(self.tmp.name)/'state'/'jimmy.sqlite3'
        self.addCleanup(lambda: setattr(STORE,'DB',self.saved_db))

    def test_operator_feedback_sent_as_context_not_calibration(self):
        import netsec_risk_v384 as r
        captured=[]
        def mock_http(url,headers,payload,timeout,max_bytes):
            captured.append(payload)
            return {'choices':[{'message':{'content':json.dumps({'severity':'amber','summary':'Follow-up',
                'observations':[],'recommended_actions':[],'confidence':'low'})},'finish_reason':'stop'}]}
        telemetry={'operator_feedback':{'items':[{'action':'expected','note':'Maintenance',
                       'created_at':'2026-11-20T20:00:00Z','expires_at':None}]}}
        answer,meta,evidence=r.analyze_model(telemetry,{}, {},'fake-model','http://192.168.1.20:3000','fake-key',
                                mock_http,json.loads,lambda s:s)
        self.assertTrue(captured)
        content=captured[0]['messages'][1]['content']
        self.assertIn('operator_supplied_context',content)
        self.assertIn('Maintenance',content)
        self.assertEqual(answer['severity'],'amber')
        self.assertNotIn('operator_feedback',evidence)

    def test_assessment_thread_audit_expiry(self):
        first=report();rid=STORE.save_report(first)
        self.assertEqual(STORE.save_report(first),rid)
        STORE.add_exchange(rid,'Why red?','Observed 22 failures; operator reports unverified.')
        self.assertEqual([r['role'] for r in STORE.messages(rid)],['user','assistant'])
        fid=STORE.add_feedback(rid,'expected',None,'Planned maintenance','netsecadmin',24)
        feed=STORE.active_feedback()
        self.assertEqual(feed[0]['id'],fid)
        self.assertEqual(feed[0]['origin'],'operator')
        self.assertIsNotNone(feed[0]['expires_at'])
        # Do not delete expired claims: preserve audit history but stop using them.
        with STORE.db() as c:c.execute('UPDATE feedback SET expires_at=? WHERE id=?',('2000-01-01T00:00:00+00:00',fid))
        self.assertEqual(STORE.active_feedback(),[])
        with STORE.db() as c:self.assertEqual(c.execute('SELECT COUNT(*) FROM feedback').fetchone()[0],1)

    def test_own_ip_requires_ip_and_no_auto_ban(self):
        rid=STORE.save_report(report())
        with self.assertRaises(ValueError):STORE.add_feedback(rid,'own_ip','', '', 'netsecadmin')
        with self.assertRaises(ValueError):STORE.add_feedback(rid,'maintenance',None,'', 'netsecadmin')
        STORE.add_feedback(rid,'own_ip','192.0.2.20','Belongs to me','netsecadmin')
        self.assertIsNone(STORE.active_feedback()[0]['expires_at'])
        source=(ROOT/'app/netsec_jimmy_api.py').read_text()
        self.assertNotIn('subprocess.',source)
        self.assertNotIn('cscli',source)
        self.assertIn("INTEL.set_label(ip,'friendly'",source)

    def test_subscription_requires_known_browser_push_host(self):
        valid={'endpoint':'https://updates.push.services.mozilla.com/wpush/v2/sample',
               'keys':{'p256dh':'A'*87,'auth':'B'*22}}
        self.assertTrue(PUSH.allowed_endpoint(valid['endpoint']))
        self.assertEqual(STORE.add_subscription(valid),STORE.subscription_id(valid['endpoint']))
        self.assertEqual(len(STORE.list_subscriptions()),1)
        for bad in ('http://fcm.googleapis.com/x','https://127.0.0.1/x',
                    'https://evil.example/x','https://web.push.apple.com@evil.example/path',
                    'https://192.168.1.1/a','https://fcm.googleapis.com:8443/x'):
            self.assertFalse(PUSH.allowed_endpoint(bad),bad)
        STORE.delete_subscription(valid['endpoint'])
        self.assertEqual(len(STORE.list_subscriptions()),0)

    def test_red_dedup_and_new_evidence(self):
        reportpath=Path(self.tmp.name)/'latest.json'
        old=PUSH.REPORT;PUSH.REPORT=reportpath;self.addCleanup(lambda:setattr(PUSH,'REPORT',old))
        t=STORE.stamp()
        reportpath.write_text(json.dumps(report(t)))
        with patch.object(PUSH,'config',return_value={'origin':'https://test.example','public_key':'abc'}),\
             patch.object(PUSH,'deliver',return_value=(1,0)) as send:
            self.assertEqual(PUSH.poll(),'sent:1/failed:0')
            self.assertEqual(PUSH.poll(),'already_active')
            changed=report(STORE.stamp())
            reportpath.write_text(json.dumps(changed))
            self.assertEqual(PUSH.poll(),'already_active')
            # Recovery ends the event, but an immediately recurring identical
            # event is suppressed for six hours.
            reportpath.write_text(json.dumps(report(STORE.stamp(),severity='amber')))
            self.assertEqual(PUSH.poll(),'not_red')
            reportpath.write_text(json.dumps(report(STORE.stamp())))
            self.assertEqual(PUSH.poll(),'quiet_or_duplicate')
            # A significantly different corroborated reason is a new event.
            reportpath.write_text(json.dumps(report(STORE.stamp(),reason='New and distinct verified outage scenario')))
            self.assertEqual(PUSH.poll(),'sent:1/failed:0')
            self.assertEqual(send.call_count,2)
            payload=send.call_args[0][0]
            self.assertNotIn('22 genuine',json.dumps(payload))
            self.assertNotIn('192.168',json.dumps(payload))

    def test_push_does_not_use_model_red_alone(self):
        sample=report()
        self.assertTrue(PUSH.event_fingerprint(sample))
        sample['risk_assessment']['method']='model interpretation only'
        self.assertIsNone(PUSH.event_fingerprint(sample))
        sample['risk_assessment']['method']='deterministic cross-check of bounded observations'
        sample['risk_assessment']['severity']='amber'
        self.assertIsNone(PUSH.event_fingerprint(sample))

    def test_authenticated_write_controls_and_cross_origin(self):
        config=Path(self.tmp.name)/'proxy.json'
        config.write_text(json.dumps({'trusted_proxy_ip':'192.0.2.10','username':'netsecadmin',
                                      'origin':'https://test.example'}))
        with patch.object(AUTH,'CONFIG',config):
            from email.message import Message
            from io import BytesIO
            class Handler(FakeResponse):
                client_address=('192.0.2.10',40000)
                def __init__(self,site='same-origin'):
                    super().__init__();self.headers=Message();self.rfile=BytesIO(b'{}')
                    for k,v in [('X-NetSec-Authenticated-User','netsecadmin'),('X-NetSec-Action','dashboard'),
                                 ('Origin','https://test.example'),('Host','test.example'),('Sec-Fetch-Site',site),
                                 ('Content-Length','2')]:self.headers[k]=v
            h=Handler(site='cross-site')
            API.post(h,'/api/jimmy/feedback')
            self.assertEqual(h.status,403)
            h=Handler()
            API.post(h,'/api/jimmy/feedback')
            self.assertEqual(h.status,400)  # No assessment ID provided

    def test_pwa_assets_network_only(self):
        self.assertEqual(json.loads((ROOT/'app/manifest.webmanifest').read_text())['display'],'standalone')
        sw=(ROOT/'app/sw.js').read_text()
        self.assertIn("e.request.mode==='navigate'",sw)
        self.assertNotIn("c.add('/index.html')",sw)
        self.assertIn("c.add('/offline.html')",sw)
        source=(ROOT/'app/app.py').read_text()
        for asset in ('/sw.js','/jimmy-ui.js','/manifest.webmanifest','/icon-192.png'):
            self.assertIn(asset,source)

if __name__=='__main__':unittest.main()
