import json
import uuid
from contextlib import contextmanager
from datetime import timedelta
from io import StringIO
from unittest.mock import patch
from django.core.management import call_command
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.conf import ConfigDict
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.events import MDMStatusReportCleanupFinished, MDMStatusReportCleanupStarted
from zentral.contrib.mdm.models import DeviceStatusReport, EnrolledDevice, EnrolledUser, Platform, UserStatusReport
from zentral.contrib.mdm.status_reports import (apply_status_report, cleanup_status_reports,
                                                get_default_status_report_retention_days, get_target_status,
                                                split_status_items)
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

    # cleanup

    def _force_status_report(self, enrolled_device=None, enrolled_user=None, *,
                             days, full_report=False, latest_full_report=False):
        kwargs = {"received_at": naive_utcnow() - timedelta(days=days),
                  "full_report": full_report,
                  "latest_full_report": latest_full_report,
                  "data": self._status_report(full_report=full_report)}
        if enrolled_user:
            return UserStatusReport.objects.create(enrolled_user=enrolled_user, **kwargs)
        return DeviceStatusReport.objects.create(enrolled_device=enrolled_device, **kwargs)

    def _force_cleanup_data(self):
        push_certificate = force_push_certificate()
        # a full report each day, from 35 days ago, and a partial report one hour after each one
        daily_device = self._force_enrolled_device(push_certificate)
        for days in range(35, 0, -1):
            self._force_status_report(daily_device, days=days, full_report=True, latest_full_report=days == 1)
            self._force_status_report(daily_device, days=days - 1 / 24)
        # the last full report 45 days ago
        old_full_device = self._force_enrolled_device(push_certificate)
        self._force_status_report(old_full_device, days=45, full_report=True, latest_full_report=True)
        self._force_status_report(old_full_device, days=40)
        self._force_status_report(old_full_device, days=2)
        # never a full report
        no_full_device = self._force_enrolled_device(push_certificate)
        self._force_status_report(no_full_device, days=80)
        self._force_status_report(no_full_device, days=10)
        # a user with two full reports before the cutoff
        self._force_status_report(enrolled_user=self.enrolled_user, days=40, full_report=True)
        self._force_status_report(enrolled_user=self.enrolled_user, days=35, full_report=True,
                                  latest_full_report=True)
        self._force_status_report(enrolled_user=self.enrolled_user, days=33)
        return daily_device, old_full_device, no_full_device

    def test_cleanup_status_reports(self):
        daily_device, old_full_device, no_full_device = self._force_cleanup_data()
        results = {}

        def result_callback(table, result):
            results[table] = result

        max_date = naive_utcnow() - timedelta(days=30)
        duration = cleanup_status_reports(max_date, result_callback, batch_size=3)
        self.assertTrue(duration > 0)
        self.assertEqual(results["mdm_devicestatusreport"]["rowcount"], 10)
        self.assertEqual(results["mdm_devicestatusreport"]["max_rows_per_target"], 60)
        self.assertEqual(results["mdm_userstatusreport"]["rowcount"], 1)
        self.assertEqual(results["mdm_userstatusreport"]["max_rows_per_target"], 2)
        # the base of the daily device is its newest full report before the cutoff
        daily_reports = DeviceStatusReport.objects.filter(enrolled_device=daily_device).order_by("pk")
        self.assertEqual(daily_reports.count(), 60)
        base = daily_reports.first()
        self.assertTrue(base.full_report)
        self.assertTrue(base.received_at < max_date)
        self.assertTrue(daily_reports.filter(latest_full_report=True).exists())
        # the old full report is the base, and nothing is deleted without a base
        self.assertEqual(DeviceStatusReport.objects.filter(enrolled_device=old_full_device).count(), 3)
        self.assertEqual(DeviceStatusReport.objects.filter(enrolled_device=no_full_device).count(), 2)
        self.assertEqual(
            list(UserStatusReport.objects.filter(enrolled_user=self.enrolled_user)
                                         .order_by("pk")
                                         .values_list("full_report", "latest_full_report")),
            [(True, True), (False, False)],
        )
        # a second run has nothing to delete
        cleanup_status_reports(max_date, result_callback, batch_size=3)
        self.assertEqual(results["mdm_devicestatusreport"]["rowcount"], 0)
        self.assertEqual(results["mdm_userstatusreport"]["rowcount"], 0)

    def test_cleanup_status_reports_no_reports(self):
        results = {}

        def result_callback(table, result):
            results[table] = result

        cleanup_status_reports(naive_utcnow() - timedelta(days=30), result_callback)
        for table in ("mdm_devicestatusreport", "mdm_userstatusreport"):
            self.assertEqual(results[table]["rowcount"], 0)
            self.assertEqual(results[table]["max_rows_per_target"], 0)

    # retention

    @contextmanager
    def mdm_conf(self, **conf):
        # the retention is read from the zentral configuration, not from the django settings
        with patch("zentral.conf.settings") as settings:
            settings.__getitem__.return_value = ConfigDict({"zentral.contrib.mdm": conf})
            yield

    def test_default_status_report_retention_days(self):
        with self.mdm_conf(status_report_retention_days=7):
            self.assertEqual(get_default_status_report_retention_days(), 7)

    def test_default_status_report_retention_days_absent(self):
        with self.mdm_conf():
            self.assertEqual(get_default_status_report_retention_days(), 30)

    def test_default_status_report_retention_days_minimum(self):
        with self.mdm_conf(status_report_retention_days=0):
            self.assertEqual(get_default_status_report_retention_days(), 1)

    def test_default_status_report_retention_days_bad_value(self):
        with self.mdm_conf(status_report_retention_days="yolo"):
            with self.assertLogs("zentral.conf", level="ERROR") as cm:
                self.assertEqual(get_default_status_report_retention_days(), 30)
        self.assertEqual(cm.records[0].getMessage(),
                         "Wrong value set status_report_retention_days, default of 30 used")

    def test_default_status_report_retention_days_boolean(self):
        with self.mdm_conf(status_report_retention_days=True):
            with self.assertLogs("zentral.conf", level="ERROR") as cm:
                self.assertEqual(get_default_status_report_retention_days(), 30)
        self.assertEqual(cm.records[0].getMessage(),
                         "Wrong value set status_report_retention_days, default of 30 used")

    # command

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_cleanup_mdm_status_reports_command(self, post_event):
        self._force_cleanup_data()
        out = StringIO()
        call_command("cleanup_mdm_status_reports", "--days", "30", stdout=out)
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("mdm_devicestatusreport: 10 deleted, max 60 per target - "))
        self.assertTrue(lines[1].startswith("mdm_userstatusreport: 1 deleted, max 2 per target - "))
        self.assertEqual(len(post_event.call_args_list), 2)
        started_event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(started_event, MDMStatusReportCleanupStarted)
        self.assertEqual(started_event.payload["cleanup"]["days"], 30)
        self.assertNotIn("tables", started_event.payload["cleanup"])
        finished_event = post_event.call_args_list[1].args[0]
        self.assertIsInstance(finished_event, MDMStatusReportCleanupFinished)
        cleanup = finished_event.payload["cleanup"]
        self.assertEqual(cleanup["days"], 30)
        self.assertEqual(cleanup["max_date"], started_event.payload["cleanup"]["max_date"])
        self.assertEqual(cleanup["tables"]["mdm_devicestatusreport"]["rowcount"], 10)
        self.assertEqual(cleanup["tables"]["mdm_userstatusreport"]["rowcount"], 1)
        self.assertTrue(cleanup["duration"] > 0)
        # the payloads must not rely on the last-resort datetime encoder of the event pipeline
        for event in (started_event, finished_event):
            json.dumps(event.payload)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_cleanup_mdm_status_reports_command_quiet(self, post_event):
        for args in (("--quiet",), ("-v", "0")):
            out = StringIO()
            call_command("cleanup_mdm_status_reports", *args, stdout=out)
            self.assertEqual(out.getvalue(), "")
        self.assertEqual(len(post_event.call_args_list), 4)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_cleanup_mdm_status_reports_command_minimum_days(self, post_event):
        call_command("cleanup_mdm_status_reports", "--days", "0", "--quiet")
        self.assertEqual(post_event.call_args_list[0].args[0].payload["cleanup"]["days"], 1)
