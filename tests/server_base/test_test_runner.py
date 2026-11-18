import unittest
from unittest.mock import patch

from django.test import SimpleTestCase

from tests.runner import ZentralTestSuite


class ZentralTestSuiteTestCase(SimpleTestCase):
    @patch("zentral.core.stores.conf.stores.clear")
    def test_stores_cleared_before_each_test_class(self, clear):
        # defined here, so that the test discovery does not collect them
        class FirstCase(unittest.TestCase):
            def test_one(self):
                pass

            def test_two(self):
                pass

        class SecondCase(unittest.TestCase):
            def test_one(self):
                pass

        suite = ZentralTestSuite([FirstCase("test_one"), FirstCase("test_two"), SecondCase("test_one")])
        result = unittest.TestResult()
        suite.run(result)
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(result.testsRun, 3)
        self.assertEqual(clear.call_count, 2)
