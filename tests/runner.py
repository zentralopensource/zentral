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


def clear_probes_cache(*args, **kwargs):
    from zentral.core.probes.conf import all_probes
    all_probes.clear()


def clear_caches():
    clear_policies_cache()
    clear_probes_cache()


def _caches_and_receivers():
    from accounts.models import Policy
    from pbac.cedar import policies_cache
    from zentral.core.probes.conf import all_probes
    from zentral.core.probes.models import Action, ProbeSource
    return ((policies_cache, Policy, clear_policies_cache),
            (all_probes, ProbeSource, clear_probes_cache),
            # a probe keeps the backends of its actions
            (all_probes, Action, clear_probes_cache))


def setup_caches():
    # In production, a notification clears a cache when a transaction changes its objects.
    # A test never commits its transaction, so the tests clear a cache when one of its objects
    # is saved or deleted, and before each test class and each test, because a rollback changes them too.
    for cache, sender, receiver in _caches_and_receivers():
        cache._sync_started = True  # no notifier callback
        post_save.connect(receiver, sender=sender, weak=False)
        post_delete.connect(receiver, sender=sender, weak=False)
    from pbac.cedar import policies_cache
    policies_cache.max_age_seconds = float("inf")


def teardown_caches():
    for cache, sender, receiver in _caches_and_receivers():
        post_save.disconnect(receiver, sender=sender)
        post_delete.disconnect(receiver, sender=sender)
        cache._sync_started = False
    from pbac.cedar import policies_cache
    del policies_cache.max_age_seconds
    clear_caches()


class ClearCachesBeforeEachTestMixin:
    def startTest(self, test):
        clear_caches()
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
        # The event stores, the policies and the probes are cached in the process. The setup of a class
        # runs after the rollback of the class before it, and with --parallel, the test classes that run
        # before this one change from run to run.
        if test.__class__ != getattr(result, "_previousTestClass", None):
            from zentral.core.stores.conf import stores
            stores.clear()
            clear_caches()
        super()._handleClassSetUp(test, result)


class ZentralTestRunner(DiscoverRunner):
    test_suite = ZentralTestSuite
    parallel_test_suite = ZentralParallelTestSuite

    def setup_test_environment(self, **kwargs):
        super().setup_test_environment(**kwargs)
        self._fast_password_hashers = override_settings(PASSWORD_HASHERS=FAST_PASSWORD_HASHERS)
        self._fast_password_hashers.enable()
        setup_caches()

    def teardown_test_environment(self, **kwargs):
        teardown_caches()
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
