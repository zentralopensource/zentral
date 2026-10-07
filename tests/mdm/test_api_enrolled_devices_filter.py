from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.models import EnrolledDevice
from zentral.contrib.mdm.api_views.enrolled_devices import EnrolledDeviceFilter
from .utils import force_ota_enrollment_session


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


class EnrolledDeviceStatusItemFiltersTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.reporting = force_ota_enrollment_session(cls.mbu, completed=True)[0].enrolled_device
        cls.reporting.status_items = {"diskmanagement.filevault.enabled": True,
                                      "passcode.is-compliant": False,
                                      "security.lockdown-mode": True}
        cls.reporting.security_info = {"FDE_Enabled": False}
        cls.reporting.save()
        cls.polled = force_ota_enrollment_session(cls.mbu, completed=True)[0].enrolled_device
        cls.polled.security_info = {"FDE_Enabled": True}
        cls.polled.save()
        cls.silent = force_ota_enrollment_session(cls.mbu, completed=True)[0].enrolled_device

    def _filter(self, **params):
        qs = EnrolledDevice.objects.filter(pk__in=[self.reporting.pk, self.polled.pk, self.silent.pk])
        return set(EnrolledDeviceFilter(params, queryset=qs).qs.values_list("pk", flat=True))

    def test_filevault_enabled_true_status_item_over_security_info(self):
        # the reporting device says True in the status item and False in the SecurityInfo result
        self.assertEqual(self._filter(filevault_enabled="true"), {self.reporting.pk, self.polled.pk})

    def test_filevault_enabled_false(self):
        self.assertEqual(self._filter(filevault_enabled="false"), set())

    def test_passcode_compliant(self):
        self.assertEqual(self._filter(passcode_compliant="false"), {self.reporting.pk})
        self.assertEqual(self._filter(passcode_compliant="true"), set())

    def test_lockdown_mode(self):
        self.assertEqual(self._filter(lockdown_mode="true"), {self.reporting.pk})
        self.assertEqual(self._filter(lockdown_mode="false"), set())

    def test_no_filter(self):
        self.assertEqual(self._filter(), {self.reporting.pk, self.polled.pk, self.silent.pk})
