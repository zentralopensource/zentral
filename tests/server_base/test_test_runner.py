import io
import logging
import unittest
from unittest.mock import patch

from django.contrib.auth.hashers import get_hasher
from django.test import SimpleTestCase, TestCase
from django.utils.crypto import get_random_string

from accounts.models import Policy
from pbac.cedar import PoliciesCache, policies_cache
from tests.runner import (clear_caches, setup_caches, teardown_caches,
                          ZentralTestRunner, ZentralTestSuite, ZentralTextTestResult)
from tests.core_probes.utils import force_action
from zentral.core.probes.conf import all_probes
from zentral.core.probes.models import ProbeSource


def build_cases():
    # built in the tests, so that the test discovery does not collect them
    class FirstCase(unittest.TestCase):
        def test_one(self):
            pass

        def test_two(self):
            pass

    class SecondCase(unittest.TestCase):
        def test_one(self):
            pass

    return [FirstCase("test_one"), FirstCase("test_two"), SecondCase("test_one")]


class ZentralTestSuiteTestCase(SimpleTestCase):
    @patch("tests.runner.clear_caches")
    @patch("zentral.core.stores.conf.stores.clear")
    def test_stores_and_caches_cleared_before_each_test_class(self, clear, clear_caches):
        suite = ZentralTestSuite(build_cases())
        # a plain result, so that only the clears of the test classes are counted
        result = unittest.TestResult()
        suite.run(result)
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(result.testsRun, 3)
        self.assertEqual(clear.call_count, 2)
        self.assertEqual(clear_caches.call_count, 2)

    @patch("tests.runner.clear_caches")
    def test_caches_cleared_before_each_test(self, clear_caches):
        suite = unittest.TestSuite(build_cases())
        result = ZentralTextTestResult(io.StringIO(), False, 0)
        suite.run(result)
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(clear_caches.call_count, 3)

    @patch("tests.runner.clear_caches")
    def test_the_test_processes_clear_the_caches_too(self, clear_caches):
        result = ZentralTestRunner.parallel_test_suite.runner_class().run(unittest.TestSuite(build_cases()))
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(clear_caches.call_count, 3)

    @patch("tests.runner.clear_caches")
    def test_the_debug_result_classes_clear_the_caches_too(self, clear_caches):
        # DebugSQLTextTestResult sets the level of this logger, and does not restore it
        logger = logging.getLogger("django.db.backends")
        self.addCleanup(logger.setLevel, logger.level)
        for kwargs in ({"debug_sql": True}, {"pdb": True}):
            with self.subTest(**kwargs):
                clear_caches.reset_mock()
                resultclass = ZentralTestRunner(**kwargs).get_resultclass()
                result = resultclass(io.StringIO(), False, 0)
                unittest.TestSuite(build_cases()).run(result)
                self.assertTrue(result.wasSuccessful())
                self.assertEqual(clear_caches.call_count, 3)

    def test_fast_password_hasher(self):
        self.assertEqual(get_hasher().algorithm, "md5")


class ZentralTestRunnerPoliciesCacheTestCase(TestCase):
    def test_a_policy_save_clears_the_cache(self):
        policies_cache.policy_set
        self.assertIsNotNone(policies_cache._policy_set)
        Policy.objects.create(name=get_random_string(12), source="permit (principal, action, resource);")
        self.assertIsNone(policies_cache._policy_set)

    def test_a_policy_delete_clears_the_cache(self):
        policy = Policy.objects.create(name=get_random_string(12), source="permit (principal, action, resource);")
        policies_cache.policy_set
        self.assertIsNotNone(policies_cache._policy_set)
        policy.delete()
        self.assertIsNone(policies_cache._policy_set)

    def test_the_cache_is_kept_between_two_reads(self):
        first = policies_cache.policy_set
        self.assertIs(policies_cache.policy_set, first)


class ZentralTestRunnerProbesCacheTestCase(TestCase):
    def test_a_probe_source_save_clears_the_cache(self):
        list(all_probes)
        self.assertIsNotNone(all_probes._probes)
        ProbeSource.objects.create(name=get_random_string(12), status=ProbeSource.ACTIVE, body={})
        self.assertIsNone(all_probes._probes)

    def test_a_probe_source_delete_clears_the_cache(self):
        probe_source = ProbeSource.objects.create(name=get_random_string(12), status=ProbeSource.ACTIVE, body={})
        list(all_probes)
        self.assertIsNotNone(all_probes._probes)
        probe_source.delete()
        self.assertIsNone(all_probes._probes)

    def test_an_action_save_clears_the_cache(self):
        action = force_action()
        list(all_probes)
        self.assertIsNotNone(all_probes._probes)
        action.description = get_random_string(12)
        action.save()
        self.assertIsNone(all_probes._probes)

    def test_an_action_delete_clears_the_cache(self):
        action = force_action()
        list(all_probes)
        self.assertIsNotNone(all_probes._probes)
        action.delete()
        self.assertIsNone(all_probes._probes)


class ZentralTestRunnerCachesTestCase(TestCase):
    def test_clear_caches_clears_the_policies_and_the_probes(self):
        policies_cache.policy_set
        list(all_probes)
        clear_caches()
        self.assertIsNone(policies_cache._policy_set)
        self.assertIsNone(all_probes._probes)

    def test_the_caches_register_no_notifier_callback(self):
        clear_caches()
        with patch("pbac.cedar.notifier") as policies_notifier, \
             patch("zentral.core.probes.conf.notifier") as probes_notifier:
            policies_cache.policy_set
            list(all_probes)
        policies_notifier.add_callback.assert_not_called()
        probes_notifier.add_callback.assert_not_called()

    def test_teardown_undoes_the_setup(self):
        self.addCleanup(setup_caches)
        teardown_caches()
        self.assertEqual(policies_cache.max_age_seconds, PoliciesCache.max_age_seconds)
        with patch("pbac.cedar.notifier") as policies_notifier, \
             patch("zentral.core.probes.conf.notifier") as probes_notifier:
            policies_cache.policy_set
            list(all_probes)
        policies_notifier.add_callback.assert_called_once()
        probes_notifier.add_callback.assert_called_once()
        # the receivers are disconnected: a save does not clear the caches
        Policy.objects.create(name=get_random_string(12), source="permit (principal, action, resource);")
        ProbeSource.objects.create(name=get_random_string(12), status=ProbeSource.ACTIVE, body={})
        self.assertIsNotNone(policies_cache._policy_set)
        self.assertIsNotNone(all_probes._probes)
