import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.models import DeviceStatusReport, EnrolledDevice, EnrolledUser, Platform, UserStatusReport
from zentral.utils.time import naive_utcnow
from .utils import force_push_certificate


class MDMStatusReportsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        push_certificate = force_push_certificate()
        cls.enrolled_device = cls._force_enrolled_device(push_certificate)
        cls.enrolled_device.os_version = "26.1"
        cls.enrolled_device.save()
        cls.enrolled_user = cls._force_enrolled_user(cls.enrolled_device)

    @staticmethod
    def _force_enrolled_device(push_certificate):
        return EnrolledDevice.objects.create(
            push_certificate=push_certificate,
            serial_number=get_random_string(12),
            platform="macOS",
            udid=str(uuid.uuid4()),
        )

    @staticmethod
    def _force_enrolled_user(enrolled_device):
        return EnrolledUser.objects.create(
            enrolled_device=enrolled_device,
            user_id=str(uuid.uuid4()).upper(),
            long_name=get_random_string(12),
            short_name=get_random_string(12),
            token=get_random_string(12).encode("utf-8"),
        )

    @staticmethod
    def _status_report(status_items=None, errors=None, full_report=False):
        status_report = {"StatusItems": status_items or {}, "Errors": errors or []}
        if full_report:
            status_report["FullReport"] = True
        return status_report

    # add status report

    def test_add_partial_status_report(self):
        status_report = self._status_report({"softwareupdate": {"install-state": "downloading"}})
        before = naive_utcnow()
        Target(self.enrolled_device).add_status_report(status_report)
        status_report_db = DeviceStatusReport.objects.get(enrolled_device=self.enrolled_device)
        self.assertEqual(status_report_db.data, status_report)
        self.assertFalse(status_report_db.full_report)
        self.assertFalse(status_report_db.latest_full_report)
        self.assertTrue(before <= status_report_db.received_at <= naive_utcnow())

    def test_add_full_status_reports(self):
        target = Target(self.enrolled_device)
        for full_report in (True, False, True):
            target.add_status_report(self._status_report(full_report=full_report))
        self.assertEqual(
            list(DeviceStatusReport.objects.filter(enrolled_device=self.enrolled_device)
                                           .order_by("pk")
                                           .values_list("full_report", "latest_full_report")),
            [(True, False), (False, False), (True, True)],
        )

    def test_add_user_status_report(self):
        Target(self.enrolled_device, self.enrolled_user).add_status_report(self._status_report(full_report=True))
        self.assertFalse(DeviceStatusReport.objects.filter(enrolled_device=self.enrolled_device).exists())
        status_report_db = UserStatusReport.objects.get(enrolled_user=self.enrolled_user)
        self.assertTrue(status_report_db.latest_full_report)

    def test_add_status_report_os_versions(self):
        for platform, os_version, stored in ((Platform.IOS, "16.7", False),
                                             (Platform.IOS, "17.0", True),
                                             (Platform.IPADOS, "16.7", False),
                                             (Platform.IPADOS, "17.0", True),
                                             (Platform.MACOS, "13.7", False),
                                             (Platform.MACOS, "14.0", True),
                                             (Platform.TVOS, "16.6", False),
                                             (Platform.TVOS, "17.0", True),
                                             (Platform.MACOS, "", False)):
            with self.subTest(platform=platform, os_version=os_version):
                DeviceStatusReport.objects.all().delete()
                self.enrolled_device.platform = platform
                self.enrolled_device.os_version = os_version
                Target(self.enrolled_device).add_status_report(self._status_report(full_report=True))
                self.assertEqual(DeviceStatusReport.objects.filter(enrolled_device=self.enrolled_device).exists(),
                                 stored)

    def test_add_user_status_report_old_os_version(self):
        self.enrolled_device.os_version = "13.7"
        Target(self.enrolled_device, self.enrolled_user).add_status_report(self._status_report(full_report=True))
        self.assertFalse(UserStatusReport.objects.exists())

    def test_purge_state_deletes_the_status_reports(self):
        Target(self.enrolled_device).add_status_report(self._status_report())
        Target(self.enrolled_device, self.enrolled_user).add_status_report(self._status_report())
        self.enrolled_device.purge_state()
        self.assertFalse(DeviceStatusReport.objects.filter(enrolled_device=self.enrolled_device).exists())
        self.assertFalse(UserStatusReport.objects.exists())
