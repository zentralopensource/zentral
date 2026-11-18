import io
import logging
import unittest
from unittest.mock import patch

from django.contrib.auth.hashers import get_hasher
from django.test import SimpleTestCase, TestCase
from django.utils.crypto import get_random_string

from accounts.models import Policy
from pbac.cedar import PoliciesCache, policies_cache
from tests.runner import (setup_policies_cache, teardown_policies_cache,
                          ZentralTestRunner, ZentralTestSuite, ZentralTextTestResult)


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
    @patch("tests.runner.clear_policies_cache")
    @patch("zentral.core.stores.conf.stores.clear")
    def test_stores_and_policies_cleared_before_each_test_class(self, clear, clear_policies_cache):
        suite = ZentralTestSuite(build_cases())
        # a plain result, so that only the clears of the test classes are counted
        result = unittest.TestResult()
        suite.run(result)
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(result.testsRun, 3)
        self.assertEqual(clear.call_count, 2)
        self.assertEqual(clear_policies_cache.call_count, 2)

    @patch("tests.runner.clear_policies_cache")
    def test_policies_cache_cleared_before_each_test(self, clear_policies_cache):
        suite = unittest.TestSuite(build_cases())
        result = ZentralTextTestResult(io.StringIO(), False, 0)
        suite.run(result)
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(clear_policies_cache.call_count, 3)

    @patch("tests.runner.clear_policies_cache")
    def test_the_test_processes_clear_the_policies_cache_too(self, clear_policies_cache):
        result = ZentralTestRunner.parallel_test_suite.runner_class().run(unittest.TestSuite(build_cases()))
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(clear_policies_cache.call_count, 3)

    @patch("tests.runner.clear_policies_cache")
    def test_the_debug_result_classes_clear_the_policies_cache_too(self, clear_policies_cache):
        # DebugSQLTextTestResult sets the level of this logger, and does not restore it
        logger = logging.getLogger("django.db.backends")
        self.addCleanup(logger.setLevel, logger.level)
        for kwargs in ({"debug_sql": True}, {"pdb": True}):
            with self.subTest(**kwargs):
                clear_policies_cache.reset_mock()
                resultclass = ZentralTestRunner(**kwargs).get_resultclass()
                result = resultclass(io.StringIO(), False, 0)
                unittest.TestSuite(build_cases()).run(result)
                self.assertTrue(result.wasSuccessful())
                self.assertEqual(clear_policies_cache.call_count, 3)

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

    def test_teardown_undoes_the_setup(self):
        self.addCleanup(setup_policies_cache)
        teardown_policies_cache()
        self.assertEqual(policies_cache.max_age_seconds, PoliciesCache.max_age_seconds)
        with patch("pbac.cedar.notifier") as notifier:
            policies_cache.policy_set
        notifier.add_callback.assert_called_once()
        # the receivers are disconnected: a save does not clear the cache
        Policy.objects.create(name=get_random_string(12), source="permit (principal, action, resource);")
        self.assertIsNotNone(policies_cache._policy_set)
