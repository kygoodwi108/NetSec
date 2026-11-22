"""Red-team tabletop regressions: CVE applicability, geography and CrowdSec state."""
import datetime as dt
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import netsec_security_intel as SEC
import netsec_risk_v384 as R
import netsec_findings as F

UTC=dt.timezone.utc
NOW=dt.datetime(2026,11,22,2,0,tzinfo=UTC)

class ThreatWargames(unittest.TestCase):
    def test_foreign_traffic_is_not_automatic_ban_or_compromise(self):
        geo=SEC.geography([{'country':'Canada','requests':150},
                           {'country':'United States','requests':40},
                           {'country':'unknown','requests':3}])
        self.assertEqual(geo['foreign_requests_sample'],40)
        self.assertEqual(geo['canadian_requests_sample'],150)
        self.assertIn('never causes a ban',geo['limitation'])
        findings=F.build({'sampled_backend_errors':0,'recent_backend_errors':0,
                          'sampled_crowdsec_timer_errors':0,'recent_crowdsec_timer_errors':0},
                         {},{'security_intelligence':{'geography':geo}})
        item=next(x for x in findings if x['id']=='international-traffic')
        self.assertEqual(item['priority'],'low')
        self.assertIn('does not prove unauthorized',item['summary'])

    def test_transmission_exception_not_web_ui_bypass(self):
        geo=SEC.geography([{'country':'United States','requests':1}])
        self.assertIn('cannot distinguish Transmission peer flows',geo['limitation'])

    def test_unknown_geo_is_not_foreign(self):
        geo=SEC.geography([{'country':'unknown','requests':50}])
        self.assertEqual(geo['foreign_requests_sample'],0)
        self.assertEqual(geo['unknown_geo_requests_sample'],50)

    def test_cve_watchlist_never_infers_exploitability_from_version(self):
        inv={'components':[{'name':'nginx','version':'1.26.3',
                            'vendor_patch_status':'unknown','features':{'http2':True,'http3':False}}]}
        watch=SEC.advisory_watch(inv)
        self.assertEqual(watch['state'],'review')
        match={x['id']:x for x in watch['items']}
        self.assertEqual(match['CVE-2026-123007']['state'],'needs_vendor_verification')
        self.assertEqual(match['CVE-2026-121810']['state'],'feature_disabled')
        self.assertNotIn('vulnerable',str(watch))

    def test_missing_inventory_is_unverified_not_safe(self):
        watch=SEC.advisory_watch({'state':'not_configured','components':[]})
        self.assertEqual(watch['state'],'inventory_needed')

    def test_recent_lapi_pull_does_not_prove_ban(self):
        b=SEC.enforcement({'state':'active','bouncers':[{'valid':True,
            'last_pull':(NOW-dt.timedelta(seconds=50)).isoformat()}]},NOW)
        self.assertEqual(b['state'],'recent_lapi_pull')
        self.assertFalse(b['enforcement_proven'])

    def test_stale_lapi_pull_is_flagged(self):
        b=SEC.enforcement({'state':'registered','bouncers':[{'valid':True,
            'last_pull':(NOW-dt.timedelta(hours=2)).isoformat()}]},NOW)
        self.assertEqual(b['state'],'unverified_or_stale')
        self.assertGreater(b['last_valid_pull_age_seconds'],300)

    def test_stale_bouncer_escalates_even_without_backend_errors(self):
        data={'http_5xx_24h':0,'security_intelligence':{'bouncer':{
            'state':'unverified_or_stale','registered_bouncers':1}}}
        v={'nginx_error_summary':{'class_counts':{},
            'recent_15m_class_counts':{}},
           'checks':[{'id':'nginx_upstreams','state':'verified'},
                     {'id':'sensitive_paths','state':'verified'}]}
        e=R.evidence(data,v,{})
        result=R.calibrate({'severity':'green','summary':'all fine','observations':[],
                            'recommended_actions':[],'confidence':'high'},e)
        self.assertEqual(result['severity'],'amber')

    def test_lapi_malformed_timestamp_not_reported_recent(self):
        b=SEC.enforcement({'state':'active','bouncers':[{'valid':True,'last_pull':'invalid'}]},NOW)
        self.assertEqual(b['state'],'unverified_or_stale')

    def test_cve_findings_require_inventory(self):
        e={'sampled_backend_errors':0,'recent_backend_errors':0,
           'sampled_crowdsec_timer_errors':0,'recent_crowdsec_timer_errors':0}
        t={'security_intelligence':{'advisories':SEC.advisory_watch({'components':[]})}}
        self.assertFalse(any(x['id']=='cve-package-review' for x in F.build(e,{},t)))

if __name__=='__main__':unittest.main()
