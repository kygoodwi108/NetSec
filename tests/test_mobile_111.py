"""Release 1.1.1: phone navigation/asset/a11y invariants; stdlib only."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'app'

class MobileUI(unittest.TestCase):
    def test_assets_are_served_and_linked(self):
        index=(APP/'index.html').read_text()
        backend=(APP/'app.py').read_text()
        for asset in ('mobile.css','mobile-ui.js'):
            self.assertTrue((APP/asset).is_file())
            self.assertIn('/'+asset,index)
            self.assertIn("'/"+asset+"'",backend)
        self.assertIn("'mobile.css':'text/css; charset=utf-8'",backend)
        self.assertIn("'mobile-ui.js':'text/javascript; charset=utf-8'",backend)
        self.assertIn("'Cache-Control', 'no-store'",backend)

    def test_navigation_reuses_original_authorization_and_routes(self):
        js=(APP/'mobile-ui.js').read_text()
        for key in ('command','jimmy','connections','investigate','traffic','intel'):
            self.assertIn("'"+key+"'",js)
        self.assertIn('target.click()',js)
        self.assertIn('MutationObserver(syncNav)',js)
        self.assertIn('aria-current',js)
        self.assertIn('Escape',js)
        self.assertIn('aria-expanded',js)
        self.assertNotIn('fetch(',js)
        self.assertNotIn('eval(',js)
        self.assertNotIn('innerHTML',js)

    def test_mobile_summary_is_a_mirror_not_a_new_risk_engine(self):
        js=(APP/'mobile-ui.js').read_text()
        for value in ('riskLabel','svcHealth','hubRequests','hubDenied'):
            self.assertIn(value,js)
        self.assertIn('textContent',js)
        self.assertIn('document.querySelector(\'#lights .bulb.red.on\')',js)
        self.assertNotIn('CrowdSec decisions add',js)

    def test_mobile_layout_no_desktop_override(self):
        css=(APP/'mobile.css').read_text()
        self.assertIn('@media (max-width:900px)',css)
        self.assertIn('safe-area-inset-bottom',css)
        self.assertIn('min-height:55px',css)
        self.assertIn('font-size:16px!important',css)
        self.assertIn('.mobile-card-table',css)
        self.assertIn('prefers-reduced-motion',css)
        self.assertIn('mobile-glance{display:none}',css)
        js=(APP/'mobile-ui.js').read_text()
        self.assertIn("headers[i]",js)
        self.assertIn('td.dataset.mobileLabel',js)
        self.assertIn('mobile-empty-row',js)

if __name__=='__main__': unittest.main()
