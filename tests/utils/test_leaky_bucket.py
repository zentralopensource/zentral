from unittest.mock import patch
from django.test import SimpleTestCase
from zentral.utils.leaky_bucket import LeakyBucket


class LeakyBucketTestCase(SimpleTestCase):
    @patch("zentral.utils.leaky_bucket.time.monotonic")
    def test_take_one_true(self, time_monotonic):
        time_monotonic.return_value = 0
        lb = LeakyBucket(10, 1)
        self.assertEqual(lb._state, (0, 10))
        time_monotonic.return_value = 1
        self.assertTrue(lb.consume())
        self.assertEqual(lb._state, (1, 9))
        self.assertTrue(lb.consume())
        self.assertEqual(lb._state, (1, 8))
        time_monotonic.return_value = 3
        self.assertTrue(lb.consume())
        self.assertEqual(lb._state, (3, 9))

    @patch("zentral.utils.leaky_bucket.time.monotonic")
    def test_take_one_no_wait(self, time_monotonic):
        time_monotonic.return_value = 0
        lb = LeakyBucket(1, 1)
        self.assertTrue(lb.consume())
        self.assertFalse(lb.consume(wait=False))

    @patch("zentral.utils.leaky_bucket.time.monotonic")
    @patch("zentral.utils.leaky_bucket.time.sleep")
    def test_take_one_wait(self, time_sleep, time_monotonic):
        time_monotonic.return_value = 0
        lb = LeakyBucket(1, 0.5)
        self.assertTrue(lb.consume())
        time_monotonic.side_effect = [0.5, 2]  # too early, wait 1.5s, then OK
        self.assertTrue(lb.consume())
        time_sleep.assert_called_once_with(1.5)
