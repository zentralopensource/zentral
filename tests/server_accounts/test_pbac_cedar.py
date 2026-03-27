from cedarpy import format_policies
from django.test import TestCase

from accounts.pbac.cedar import authorize_requests, PoliciesCache
from .utils import force_policy


class PBACCedarTestCase(TestCase):
    def test_authorize_requests_no_requests(self):
        self.assertIsNone(authorize_requests([]))

    def test_policies_cache_with_sync(self):
        force_policy()
        pc = PoliciesCache(with_sync=True)
        self.assertFalse(pc._sync_started)
        self.assertIsNone(pc._last_refresh_ts)
        # not cached
        self.assertEqual(
            pc.all_policies_concatenated,
            format_policies('permit (principal in Role::"0", action, resource);').strip(),
        )
        self.assertTrue(pc._sync_started)
        ts = pc._last_refresh_ts
        self.assertIsNotNone(ts)
        # cached
        self.assertEqual(
            pc.all_policies_concatenated,
            format_policies('permit (principal in Role::"0", action, resource);').strip(),
        )
        self.assertEqual(ts, pc._last_refresh_ts)
        # clear
        pc.clear()
        self.assertIsNone(pc._concatenated_policies)
