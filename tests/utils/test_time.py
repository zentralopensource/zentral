from django.test import SimpleTestCase
from zentral.utils.time import duration_repr


class TimeTestCase(SimpleTestCase):
    def test_empty(self):
        self.assertEqual("", duration_repr(0))

    def test_full(self):
        self.assertEqual("14d 23h 24m 31s", duration_repr(1293871))
