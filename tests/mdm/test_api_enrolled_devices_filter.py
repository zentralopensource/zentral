from django.test import TestCase

from zentral.contrib.mdm.models import EnrolledDevice
from zentral.contrib.mdm.api_views.enrolled_devices import EnrolledDeviceFilter


class EnrolledDeviceFilterUnitTestCase(TestCase):
    def test_filter_short_name_empty_value_returns_queryset_unchanged(self):
        qs = EnrolledDevice.objects.order_by("pk")
        f = EnrolledDeviceFilter()

        res = f.filter_short_name(qs, "short_name", "")
        self.assertEqual(list(res), list(qs))

    def test_filter_email_empty_value_returns_queryset_unchanged(self):
        qs = EnrolledDevice.objects.order_by("pk")
        f = EnrolledDeviceFilter()

        res = f.filter_email(qs, "email", "")

        self.assertEqual(list(res), list(qs))
