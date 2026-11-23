import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'app'))
import netsec_patchmon_intel as pm


class PatchMonInventoryTests(unittest.TestCase):
    target = ('patchmon.example.org', '192.168.1.2')
    url = 'http://192.168.1.3:3000'

    def test_inventory_and_jimmy_evidence(self):
        sample = {'hosts': [{'hostname': 'worker', 'updates_count': 3,
                             'security_updates_count': 2, 'needs_reboot': True,
                             'reporting_state': 'overdue'}]}
        with patch.object(pm, '_credentials', return_value=(('key', 'secret'), self.target)), \
             patch.object(pm, '_get', return_value=sample):
            result = pm.snapshot(self.url, force=True)
        self.assertEqual(result['hosts_stale_or_overdue'], 1)
        self.assertEqual(result['hosts_need_reboot'], 1)
        self.assertEqual(pm.for_model(result)['hosts'][0]['security_updates'], 2)

    def test_denied_inventory(self):
        with patch.object(pm, '_get', side_effect=pm.PatchMonHTTPError(403)):
            result = pm._load_snapshot(self.target, ('key', 'secret'))
        self.assertEqual(result['state'], 'access_denied')
        self.assertNotIn('hosts', pm.for_model(result))

    def test_endpoint_validation(self):
        self.assertEqual(pm.endpoint(*self.target), self.target)
        for target in [('bad/host', self.target[1]), (self.target[0], '8.8.8.8')]:
            with self.assertRaises(ValueError):
                pm.endpoint(*target)
