"""Regression cases for Jimmy incident chronology and risk calibration."""
import datetime as dt
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import netsec_risk_v384 as R
import netsec_jimmy_checks as C
import netsec_findings as F

class IncidentLifecycle(unittest.TestCase):
    def _evidence(self,recent):
        return R.evidence(
            {'http_5xx_24h':793,'requests_24h':2000},
            {'generated_at':dt.datetime.now(dt.timezone.utc).isoformat(),
             'nginx_error_summary':{'class_counts':{
                 'upstream_connection_failure':466,
                 'crowdsec_timer_connectivity':72},
                 'recent_15m_class_counts':recent},
             'checks':[{'id':'nginx_upstreams','state':'verified'},
                       {'id':'sensitive_paths','state':'verified'}]},
            {'generated_at':dt.datetime.now(dt.timezone.utc).isoformat()})

    def _reply(self):
        return {'severity':'amber','summary':'Errors observed',
                'observations':[],'recommended_actions':[],
                'confidence':'medium'}

    def test_historical_patchmon_not_automatically_amber(self):
        e=self._evidence({})
        result=R.calibrate(self._reply(),e)
        self.assertEqual(result['severity'],'green')
        self.assertEqual(result['risk_assessment']['sample_counts']['real_upstream_errors'],466)
        self.assertEqual(result['risk_assessment']['sample_counts']['recent_15m_upstream_errors'],0)
        f=F.build(e,{}, {})
        self.assertTrue(any(x['id']=='nginx-upstream-resolved' for x in f))
        self.assertFalse(any(x['id']=='nginx-upstream' for x in f))

    def test_active_backend_remains_amber(self):
        e=self._evidence({'upstream_connection_failure':25})
        self.assertEqual(R.calibrate(self._reply(),e)['severity'],'amber')

    def test_active_crowdsec_remains_amber(self):
        e=self._evidence({'crowdsec_timer_connectivity':30})
        self.assertEqual(R.calibrate(self._reply(),e)['severity'],'amber')

    def test_fresh_down_services_override_quiet_logs(self):
        e=self._evidence({})
        e['service_health']={'fresh':True,'down':1}
        self.assertEqual(R.calibrate(self._reply(),e)['severity'],'amber')

    def test_missing_recent_window_uses_conservative_legacy_logic(self):
        e=self._evidence({})
        e.pop('recent_backend_errors');e.pop('recent_crowdsec_timer_errors')
        self.assertEqual(R.calibrate(self._reply(),e)['severity'],'amber')

    def test_error_time_bounds_and_last_15_minutes(self):
        now=dt.datetime.now(dt.timezone.utc)
        old=(now-dt.timedelta(hours=2)).strftime('%Y/%m/%d %H:%M:%S')
        recent=(now-dt.timedelta(minutes=2)).strftime('%Y/%m/%d %H:%M:%S')
        line=lambda t:f'{t} [error] 123#123: *1 connect() failed (111: Connection refused) while connecting to upstream, upstream: "http://192.168.2.119:3000/"'
        def mocked(path,size=1500000):
            return [line(old),line(recent)] if path.name=='error.log' else []
        with patch.object(C,'_recent_lines',side_effect=mocked):
            d=C._errors(tz='UTC')
        self.assertEqual(d['class_counts']['upstream_connection_failure'],2)
        self.assertEqual(d['recent_15m_class_counts']['upstream_connection_failure'],1)
        self.assertIn('upstream_connection_failure',d['last_seen_by_class'])

if __name__=='__main__':
    unittest.main()
