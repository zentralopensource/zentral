import multiprocessing
import unittest

from django.db import connections
from django.db.models.signals import post_delete, post_save
from django.test.runner import DiscoverRunner, ParallelTestSuite, RemoteTestResult, RemoteTestRunner
from django.test.utils import override_settings


# Python 3.14 starts the processes with forkserver on Linux, and the Django test runner
# runs the tests in parallel only with fork or spawn. The test command imports this module
# before it replaces --parallel auto with a number of processes.
multiprocessing.set_start_method("fork", force=True)


# PBKDF2 is slow on purpose, and the tests do not need it.
FAST_PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]


def clear_policies_cache(*args, **kwargs):
    from pbac.cedar import policies_cache
    policies_cache.clear()


def setup_policies_cache():
    # In production, a notification clears the cache when a transaction changes the policies.
    # A test never commits its transaction, so the tests clear the cache when a policy is saved
    # or deleted, and before each test class and each test, because a rollback changes the policies too.
    from accounts.models import Policy
    from pbac.cedar import policies_cache
    policies_cache._sync_started = True  # no notifier callback
    policies_cache.max_age_seconds = float("inf")
    post_save.connect(clear_policies_cache, sender=Policy, weak=False)
    post_delete.connect(clear_policies_cache, sender=Policy, weak=False)


def teardown_policies_cache():
    from accounts.models import Policy
    from pbac.cedar import policies_cache
    post_save.disconnect(clear_policies_cache, sender=Policy)
    post_delete.disconnect(clear_policies_cache, sender=Policy)
    policies_cache._sync_started = False
    del policies_cache.max_age_seconds
    clear_policies_cache()


class ClearCachesBeforeEachTestMixin:
    def startTest(self, test):
        clear_policies_cache()
        super().startTest(test)


class ZentralTextTestResult(ClearCachesBeforeEachTestMixin, unittest.TextTestResult):
    pass


class ZentralRemoteTestResult(ClearCachesBeforeEachTestMixin, RemoteTestResult):
    pass


class ZentralRemoteTestRunner(RemoteTestRunner):
    resultclass = ZentralRemoteTestResult


class ZentralParallelTestSuite(ParallelTestSuite):
    runner_class = ZentralRemoteTestRunner


class ZentralTestSuite(unittest.TestSuite):
    def _handleClassSetUp(self, test, result):
        # The event stores and the policies are cached in the process. The setup of a class runs
        # after the rollback of the class before it, and with --parallel, the test classes that run
        # before this one change from run to run.
        if test.__class__ != getattr(result, "_previousTestClass", None):
            from zentral.core.stores.conf import stores
            stores.clear()
            clear_policies_cache()
        super()._handleClassSetUp(test, result)


class ZentralTestRunner(DiscoverRunner):
    test_suite = ZentralTestSuite
    parallel_test_suite = ZentralParallelTestSuite

    def setup_test_environment(self, **kwargs):
        super().setup_test_environment(**kwargs)
        self._fast_password_hashers = override_settings(PASSWORD_HASHERS=FAST_PASSWORD_HASHERS)
        self._fast_password_hashers.enable()
        setup_policies_cache()

    def teardown_test_environment(self, **kwargs):
        teardown_policies_cache()
        self._fast_password_hashers.disable()
        super().teardown_test_environment(**kwargs)

    def get_resultclass(self):
        resultclass = super().get_resultclass()
        if resultclass is None:
            return ZentralTextTestResult
        return type(f"Zentral{resultclass.__name__}", (ClearCachesBeforeEachTestMixin, resultclass), {})

    def setup_databases(self, **kwargs):
        # With --keepdb, Django keeps a clone that exists, and does not migrate it.
        # A new clone of the migrated test database is fast.
        if self.keepdb and self.parallel > 1:
            for alias in kwargs.get("aliases", ()):
                creation = connections[alias].creation
                test_db_name = creation._get_test_db_name()
                with creation._nodb_cursor() as cursor:
                    for index in range(1, self.parallel + 1):
                        clone_name = connections[alias].ops.quote_name(f"{test_db_name}_{index}")
                        cursor.execute(f"DROP DATABASE IF EXISTS {clone_name}")
        return super().setup_databases(**kwargs)
