import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.models import DeviceStatusReport, EnrolledDevice, EnrolledUser, Platform, UserStatusReport
from zentral.contrib.mdm.status_reports import apply_status_report, get_target_status, split_status_items
from zentral.utils.time import naive_utcnow
from .utils import force_push_certificate


STATUS_ITEMS = [
    "device.operating-system.supplemental.extra-version",
    "device.operating-system.version",
    "diskmanagement.filevault.enabled",
    "management.client-capabilities",
    "services.background-task",
    "softwareupdate.install-state",
    "softwareupdate.pending-version",
]


class MDMStatusReportsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        push_certificate = force_push_certificate()
        cls.enrolled_device = cls._force_enrolled_device(push_certificate)
        cls.enrolled_device.os_version = "26.1"
        cls.enrolled_device.client_capabilities = {"supported-payloads": {"status-items": STATUS_ITEMS}}
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

    # split status items

    def test_split_status_items(self):
        self.assertEqual(
            split_status_items(
                {"device": {"operating-system": {"supplemental": {"extra-version": "(a)"}, "version": "26.7.2"}},
                 "management": {"client-capabilities": {"supported-versions": ["1.0.0"]}},
                 "unknown": {"empty": {}, "tree": {"leaf": 1}}},
                set(STATUS_ITEMS),
            ),
            {"device.operating-system.supplemental.extra-version": "(a)",
             "device.operating-system.version": "26.7.2",
             "management.client-capabilities": {"supported-versions": ["1.0.0"]},
             "unknown.empty": {},
             "unknown.tree.leaf": 1},
        )

    # rebuild

    def test_get_target_status_no_status_reports(self):
        self.assertIsNone(get_target_status(Target(self.enrolled_device)))

    def test_get_target_status_without_full_report(self):
        target = Target(self.enrolled_device)
        target.add_status_report(self._status_report({"softwareupdate": {"install-state": "downloading"}}))
        target.add_status_report(self._status_report({"diskmanagement": {"filevault": {"enabled": True}}}))
        self.assertEqual(
            get_target_status(target),
            {"items": {"diskmanagement.filevault.enabled": True,
                       "softwareupdate.install-state": "downloading"},
             "errors": {}},
        )

    def test_get_target_status(self):
        target = Target(self.enrolled_device)
        # an older full report, replaced by the next one
        target.add_status_report(self._status_report({"softwareupdate": {"install-state": "failed"}},
                                                     full_report=True))
        target.add_status_report(self._status_report(
            {"device": {"operating-system": {"version": "26.7.1"}},
             "diskmanagement": {"filevault": {"enabled": True}},
             "services": {"background-task": [{"identifier": "A", "path": "/a"},
                                              {"identifier": "B", "path": "/b"}]},
             "softwareupdate": {"install-state": "prepared",
                                "pending-version": {"build-version": "25G332", "os-version": "26.7.2"}}},
            full_report=True,
        ))
        target.add_status_report(self._status_report(
            {"device": {"operating-system": {"version": "26.7.2"}},
             "services": {"background-task": [{"identifier": "C", "path": "/a"},
                                              {"identifier": "A", "_removed": True}]},
             "softwareupdate": {"install-state": "none", "pending-version": {}}},
        ))
        target.add_status_report(self._status_report(
            errors=[{"StatusItem": "diskmanagement.filevault.enabled",
                     "Reasons": [{"Code": "Error.MissingStatusValue"}]}],
        ))
        self.assertEqual(
            get_target_status(target),
            {"items": {"device.operating-system.version": "26.7.2",
                       "services.background-task": [{"identifier": "B", "path": "/b"},
                                                    {"identifier": "C", "path": "/a"}],
                       "softwareupdate.install-state": "none"},
             "errors": {"diskmanagement.filevault.enabled": [{"Code": "Error.MissingStatusValue"}]}},
        )
        target.add_status_report(self._status_report({"diskmanagement": {"filevault": {"enabled": False}}}))
        status = get_target_status(target)
        self.assertFalse(status["items"]["diskmanagement.filevault.enabled"])
        self.assertEqual(status["errors"], {})

    def test_apply_status_report_error_without_reasons(self):
        status = apply_status_report(
            {"items": {"softwareupdate.install-state": "none"}, "errors": {}},
            self._status_report(errors=[{"StatusItem": "softwareupdate.install-state"}]),
            set(STATUS_ITEMS),
        )
        self.assertEqual(status, {"items": {}, "errors": {"softwareupdate.install-state": []}})

    def test_apply_status_report_unknown_list(self):
        status = apply_status_report(
            {"items": {"unknown.list": [1, 2]}, "errors": {}},
            self._status_report({"unknown": {"list": [3]}, "softwareupdate": {"install-state": None}}),
            set(STATUS_ITEMS),
        )
        self.assertEqual(status, {"items": {"unknown.list": [3]}, "errors": {}})
