import multiprocessing
import unittest

from django.db import connections
from django.test.runner import DiscoverRunner


# Python 3.14 starts the processes with forkserver on Linux, and the Django test runner
# runs the tests in parallel only with fork or spawn. The test command imports this module
# before it replaces --parallel auto with a number of processes.
multiprocessing.set_start_method("fork", force=True)


class ZentralTestSuite(unittest.TestSuite):
    def _handleClassSetUp(self, test, result):
        # The event stores are cached in the process, and with --parallel,
        # the test classes that run before this one change from run to run.
        if test.__class__ != getattr(result, "_previousTestClass", None):
            from zentral.core.stores.conf import stores
            stores.clear()
        super()._handleClassSetUp(test, result)


class ZentralTestRunner(DiscoverRunner):
    test_suite = ZentralTestSuite

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
