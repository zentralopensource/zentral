from datetime import datetime, timedelta
import json
from unittest.mock import patch
import uuid
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret, MachineSnapshot, MetaBusinessUnit, Tag, MachineTag
from zentral.contrib.munki.events import MunkiInstallEvent, MunkiInstallFailedEvent, MunkiScriptCheckStatusUpdated
from zentral.contrib.munki.incidents import IncidentUpdate, MunkiInstallFailedIncident
from zentral.contrib.munki.models import (Configuration, EnrolledMachine, Enrollment,
                                          ManagedInstall, MunkiState, ScriptCheck)
from zentral.core.compliance_checks.models import MachineStatus
from zentral.core.incidents.models import Incident, MachineIncident, Severity, Status
from .utils import force_script_check


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MunkiAPIViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.business_unit = cls.meta_business_unit.create_enrollment_business_unit()
        cls.configuration = Configuration.objects.create(
            name=get_random_string(12),
            auto_failed_install_incidents=True,
            auto_reinstall_incidents=True
        )
        cls.enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=cls.meta_business_unit)
        cls.enrollment_secret.tags.set([Tag.objects.create(name=get_random_string(12)) for _ in range(2)])
        cls.enrollment = Enrollment.objects.create(configuration=cls.configuration, secret=cls.enrollment_secret)

    # utility methods

    def _make_enrolled_machine(self, tag_name=None):
        em = EnrolledMachine.objects.create(enrollment=self.enrollment,
                                            serial_number=get_random_string(32),
                                            token=get_random_string(64))
        if tag_name:
            tag = Tag.objects.create(name=tag_name)
            MachineTag.objects.create(serial_number=em.serial_number, tag=tag)
        return em

    def _post_as_json(self, url, data, **extra):
        return self.client.post(url,
                                json.dumps(data),
                                content_type="application/json",
                                **extra)

    # enroll

    def test_enroll_bad_request_empty(self):
        response = self._post_as_json(reverse("munki:enroll"), {})
        self.assertEqual(response.status_code, 400)

    def test_enroll_bad_request_bad_secret(self):
        serial_number = get_random_string(32)
        response = self._post_as_json(reverse("munki:enroll"),
                                      {"secret": "yolo",
                                       "uuid": str(uuid.uuid4()),
                                       "serial_number": serial_number})
        self.assertEqual(response.status_code, 400)

    def test_enroll_ok(self):
        serial_number = get_random_string(32)
        response = self._post_as_json(reverse("munki:enroll"),
                                      {"secret": self.enrollment.secret.secret,
                                       "uuid": str(uuid.uuid4()),
                                       "serial_number": serial_number})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/json")
        json_response = response.json()
        self.assertCountEqual(["token"], json_response.keys())
        token = json_response["token"]
        enrolled_machine = EnrolledMachine.objects.get(enrollment=self.enrollment, serial_number=serial_number)
        self.assertEqual(token, enrolled_machine.token)
        self.assertEqual(
            set(mt.tag for mt in MachineTag.objects.select_related("tag").filter(serial_number=serial_number)),
            set(self.enrollment.secret.tags.all())
        )

    # job details

    def test_job_details_missing_auth_header_err(self):
        response = self._post_as_json(reverse("munki:job_details"), {})
        self.assertEqual(response.status_code, 403)

    def test_job_details_wrong_auth_token_err(self):
        response = self._post_as_json(reverse("munki:job_details"), {},
                                      HTTP_AUTHORIZATION=get_random_string(23))
        self.assertEqual(response.status_code, 403)

    def test_job_details_enrolled_machine_does_not_exist_err(self):
        response = self._post_as_json(reverse("munki:job_details"), {},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(get_random_string(34)))
        self.assertEqual(response.status_code, 403)

    def test_job_details_missing_serial_number_err(self):
        enrolled_machine = self._make_enrolled_machine()
        response = self._post_as_json(reverse("munki:job_details"), {},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertEqual(response.status_code, 403)

    def test_job_details_machine_conflict_err(self):
        enrolled_machine = self._make_enrolled_machine()
        data_sn = get_random_string(9)
        response = self._post_as_json(reverse("munki:job_details"),
                                      {"machine_serial_number": data_sn},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertEqual(response.status_code, 403)

    def test_job_details(self):
        enrolled_machine = self._make_enrolled_machine()
        response = self._post_as_json(reverse("munki:job_details"),
                                      {"machine_serial_number": enrolled_machine.serial_number},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertEqual(response.status_code, 200)
        expected_response = {
            "apps_full_info_shard": self.configuration.inventory_apps_full_info_shard,
            "incidents": [],
            "tags": [],
        }
        self.assertEqual(expected_response, response.json())

    def test_job_details_with_collected_condition_keys(self):
        enrolled_machine = self._make_enrolled_machine()
        self.configuration.collected_condition_keys = ["un"]
        self.configuration.save()
        response = self._post_as_json(reverse("munki:job_details"),
                                      {"machine_serial_number": enrolled_machine.serial_number},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertEqual(response.status_code, 200)
        expected_response = {
            "apps_full_info_shard": self.configuration.inventory_apps_full_info_shard,
            "collected_condition_keys": ["un"],
            "incidents": [],
            "tags": [],
        }
        self.assertEqual(expected_response, response.json())

    def test_job_details_with_principal_user_detection(self):
        enrolled_machine = self._make_enrolled_machine()
        self.configuration.principal_user_detection_sources = ["Google Chrome"]
        self.configuration.principal_user_detection_domains = ["zentral.com"]
        self.configuration.save()
        response = self._post_as_json(reverse("munki:job_details"),
                                      {"machine_serial_number": enrolled_machine.serial_number},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["principal_user_detection"],
            {"sources": ["Google Chrome"],
             "domains": ["zentral.com"]}
        )

    def test_job_details_with_open_incident(self):
        enrolled_machine = self._make_enrolled_machine()
        # one open, one closed incident
        for status in (Status.OPEN, Status.CLOSED):
            i = Incident.objects.create(
                incident_type=get_random_string(12),
                key={"un": get_random_string(12)},
                status=status.value,
                status_time=datetime.utcnow(),
                severity=Severity.MAJOR.value
            )
            MachineIncident.objects.create(
                incident=i,
                serial_number=enrolled_machine.serial_number,
                status=status.value,
                status_time=datetime.utcnow()
            )
        response = self._post_as_json(reverse("munki:job_details"),
                                      {"machine_serial_number": enrolled_machine.serial_number},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertEqual(response.status_code, 200)
        expected_response = {
            "apps_full_info_shard": self.configuration.inventory_apps_full_info_shard,
            "incidents": ['base incident ∅'],
            "tags": [],
        }
        self.assertEqual(expected_response, response.json())

    def test_job_details_conflict(self):
        enrolled_machine = self._make_enrolled_machine()
        response = self._post_as_json(reverse("munki:job_details"),
                                      {"machine_serial_number": get_random_string(3)},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.munki.views.logger.error")
    def test_job_details_bad_os_version(self, logger_error):
        enrolled_machine = self._make_enrolled_machine()
        force_script_check()
        response = self._post_as_json(reverse("munki:job_details"),
                                      {"machine_serial_number": enrolled_machine.serial_number,
                                       "os_version": "yolo",
                                       "arch": "amd64"},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        logger_error.assert_called_once_with("Machine %s: could not build comparable OS version",
                                             enrolled_machine.serial_number)
        self.assertNotIn("script_checks", response.json())

    @patch("zentral.contrib.munki.views.logger.error")
    def test_job_details_unknown_arch_version(self, logger_error):
        enrolled_machine = self._make_enrolled_machine()
        force_script_check()
        response = self._post_as_json(reverse("munki:job_details"),
                                      {"machine_serial_number": enrolled_machine.serial_number,
                                       "os_version": "14.1",
                                       "arch": "yolo"},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        logger_error.assert_called_once_with("Machine %s: unknown arch",
                                             enrolled_machine.serial_number)
        self.assertNotIn("script_checks", response.json())

    def test_job_details_first_time_script_check(self):
        enrolled_machine = self._make_enrolled_machine()
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(2)]
        for tag in tags:
            MachineTag.objects.create(serial_number=enrolled_machine.serial_number, tag=tag)
        sc = force_script_check(
            type=ScriptCheck.Type.ZSH_BOOL,
            source="echo true",
            expected_result="t",
            min_os_version="14",
            max_os_version="15",
            arch_arm64=True,
            arch_amd64=False,
            tags=tags[:1]
        )
        force_script_check(max_os_version="14.0.1", arch_arm64=True)  # max OS version
        response = self._post_as_json(reverse("munki:job_details"),
                                      {"machine_serial_number": enrolled_machine.serial_number,
                                       "os_version": "14.1",
                                       "arch": "arm64"},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertEqual(
            response.json()["script_checks"],
            [{'pk': sc.pk, 'version': 1, 'type': 'ZSH_BOOL', 'source': 'echo true', 'expected_result': True}]
        )

    def test_job_details_first_time_script_check_amd64(self):
        enrolled_machine = self._make_enrolled_machine()
        sc = force_script_check(
            type=ScriptCheck.Type.ZSH_BOOL,
            source="echo true",
            expected_result="t",
            arch_arm64=False,
            arch_amd64=True,
        )
        force_script_check(min_os_version="15", arch_amd64=True)  # min OS version
        response = self._post_as_json(reverse("munki:job_details"),
                                      {"machine_serial_number": enrolled_machine.serial_number,
                                       "os_version": "14.1",
                                       "arch": "amd64"},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertEqual(
            response.json()["script_checks"],
            [{'pk': sc.pk, 'version': 1, 'type': 'ZSH_BOOL', 'source': 'echo true', 'expected_result': True}]
        )

    def test_job_details_second_time_too_early_no_script_check(self):
        enrolled_machine = self._make_enrolled_machine()
        tag = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number=enrolled_machine.serial_number, tag=tag)
        force_script_check(
            type=ScriptCheck.Type.ZSH_BOOL,
            source="echo true",
            expected_result="t",
        )
        MunkiState.objects.create(machine_serial_number=enrolled_machine.serial_number,
                                  last_script_checks_run=datetime.utcnow())
        response = self._post_as_json(reverse("munki:job_details"),
                                      {"machine_serial_number": enrolled_machine.serial_number,
                                       "os_version": "14.1",
                                       "arch": "arm64"},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertNotIn("script_checks", response.json())

    def test_job_details_second_time_script_check(self):
        enrolled_machine = self._make_enrolled_machine()
        tag = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number=enrolled_machine.serial_number, tag=tag)
        sc = force_script_check(
            type=ScriptCheck.Type.ZSH_INT,
            source="echo 10",
            expected_result="10",
        )
        configuration = enrolled_machine.enrollment.configuration
        last_script_checks_run = (
            datetime.utcnow()
            - timedelta(seconds=configuration.script_checks_run_interval_seconds)
            - timedelta(seconds=1)
        )
        MunkiState.objects.create(machine_serial_number=enrolled_machine.serial_number,
                                  last_script_checks_run=last_script_checks_run)
        response = self._post_as_json(reverse("munki:job_details"),
                                      {"machine_serial_number": enrolled_machine.serial_number,
                                       "os_version": "14.1",
                                       "arch": "arm64"},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertEqual(
            response.json()["script_checks"],
            [{'pk': sc.pk, 'version': 1, 'type': 'ZSH_INT', 'source': 'echo 10', 'expected_result': 10}]
        )

    # post job

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_job(self, post_event):
        tag_name = get_random_string(12)
        enrolled_machine = self._make_enrolled_machine(tag_name=tag_name)
        computer_name = get_random_string(45)
        report_sha1sum = 40 * "0"

        # no managed installs for the machine
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=enrolled_machine.serial_number)
        self.assertEqual(mi_qs.count(), 0)

        # post job with failed install
        response = self._post_as_json(reverse("munki:post_job"),
                                      {"machine_snapshot": {"serial_number": enrolled_machine.serial_number,
                                                            "system_info": {"computer_name": computer_name},
                                                            "extra_facts": {"yolo": "\u0000fomo",
                                                                            "un": None}},
                                       "last_seen_report_found": True,
                                       "reports": [{"start_time": "2018-01-01 00:00:00 +0000",
                                                    "end_time": "2018-01-01 00:01:00 +0000",
                                                    "basename": "report2018",
                                                    "run_type": "auto",
                                                    "sha1sum": report_sha1sum,
                                                    "events": [("2021-11-15T14:47:37Z",
                                                                {"name": "YoloApp",
                                                                 "display_name": "Yolo App",
                                                                 "version": "1.2.3",
                                                                 "status": 1,
                                                                 "type": "install"})]}]},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertEqual(response.status_code, 200)

        # check reference = serial number
        ms = MachineSnapshot.objects.current().get(serial_number=enrolled_machine.serial_number)
        ms2 = MachineSnapshot.objects.current().get(reference=enrolled_machine.serial_number)
        self.assertEqual(ms, ms2)

        # check computer name
        self.assertEqual(ms.system_info.computer_name, computer_name)

        # check extra facts
        self.assertEqual(ms.extra_facts, {"yolo": "fomo"})

        # check all events linked to machine
        for call_args in post_event.call_args_list:
            event = call_args.args[0]
            self.assertEqual(event.metadata.machine_serial_number, enrolled_machine.serial_number)

        # check last event is munki event with incident update for the failed install
        last_event = post_event.call_args.args[0]
        self.assertIsInstance(last_event, MunkiInstallFailedEvent)
        self.assertEqual(len(last_event.metadata.incident_updates), 1)
        incident_update = last_event.metadata.incident_updates[0]
        self.assertEqual(
            incident_update,
            IncidentUpdate(
                "munki_install_failed",
                {"munki_pkginfo_name": "YoloApp",
                 "munki_pkginfo_version": "1.2.3"},
                MunkiInstallFailedIncident.severity
            )
        )

        # check managed installs
        self.assertEqual(mi_qs.count(), 1)
        mi = mi_qs.first()
        self.assertEqual(mi.name, "YoloApp")
        self.assertIsNone(mi.installed_version)
        self.assertIsNone(mi.installed_at)
        self.assertFalse(mi.reinstall)
        self.assertEqual(mi.failed_version, "1.2.3")
        self.assertEqual(mi.failed_at, datetime(2021, 11, 15, 14, 47, 37))

        # check new job
        response = self._post_as_json(reverse("munki:job_details"),
                                      {"machine_serial_number": enrolled_machine.serial_number},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"apps_full_info_shard": self.configuration.inventory_apps_full_info_shard,
             "managed_installs": True,
             "incidents": [],
             "tags": [tag_name],
             "last_seen_sha1sum": report_sha1sum}
        )

    def test_post_job_duplicated_profile(self):
        enrolled_machine = self._make_enrolled_machine()
        profile = {
            "uuid": "a62a458d-6cdb-4b3c-a440-2ac3129022db",
            "identifier": "un.deux.trois",
            "display_name": "Un Deux Trois",
            "description": "Un Deux Trois description",
            "organization": "Zentral",
            "removal_disallowed": True,
            "verified": True,
            "payloads": [
                {"uuid": "660d9eaf-3326-44bc-ae70-3a938bdf67bd",
                 "identifier": "un.deux.trois.quatre",
                 "display_name": "Un Deux Trois Quatre",
                 "description": "Un Deux Trois Quatre description",
                 "type": "com.apple.ManagedClient.preferences"}
            ]
        }
        response = self._post_as_json(
            reverse("munki:post_job"),
            {"machine_snapshot": {"serial_number": enrolled_machine.serial_number,
                                  "system_info": {"computer_name": "yolo"},
                                  "profiles": [profile, profile]},
             "reports": []},
            HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token)
        )
        self.assertEqual(response.status_code, 200)
        ms = MachineSnapshot.objects.current().get(serial_number=enrolled_machine.serial_number)
        self.assertEqual(ms.profiles.count(), 1)
        db_profile = ms.profiles.first()
        self.assertEqual(db_profile.uuid, profile["uuid"])

    def test_post_job_missing_patch_number(self):
        enrolled_machine = self._make_enrolled_machine()
        response = self._post_as_json(reverse("munki:post_job"),
                                      {"machine_snapshot": {"serial_number": enrolled_machine.serial_number,
                                                            "system_info": {"computer_name": get_random_string(12)},
                                                            "os_version": {"name": "macOS", "major": 12, "minor": 5}},
                                       "last_seen_report_found": True,
                                       "reports": []},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertEqual(response.status_code, 200)

        # patch 0
        ms = MachineSnapshot.objects.current().get(serial_number=enrolled_machine.serial_number)
        self.assertEqual(ms.os_version.patch, 0)

    def test_post_job_with_patch_number(self):
        enrolled_machine = self._make_enrolled_machine()
        response = self._post_as_json(reverse("munki:post_job"),
                                      {"machine_snapshot": {"serial_number": enrolled_machine.serial_number,
                                                            "system_info": {"computer_name": get_random_string(12)},
                                                            "os_version": {"name": "macOS",
                                                                           "major": 12, "minor": 3, "patch": 1}},
                                       "last_seen_report_found": True,
                                       "reports": []},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertEqual(response.status_code, 200)

        # patch 1
        ms = MachineSnapshot.objects.current().get(serial_number=enrolled_machine.serial_number)
        self.assertEqual(ms.os_version.patch, 1)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_job_with_wipe(self, post_event):
        tag_name = get_random_string(12)
        enrolled_machine = self._make_enrolled_machine(tag_name=tag_name)
        computer_name = get_random_string(45)

        # no managed installs for the machine
        mi_qs = ManagedInstall.objects.filter(machine_serial_number=enrolled_machine.serial_number)
        self.assertEqual(mi_qs.count(), 0)

        # post job with OK install
        response = self._post_as_json(reverse("munki:post_job"),
                                      {"machine_snapshot": {"serial_number": enrolled_machine.serial_number,
                                                            "system_info": {"computer_name": computer_name},
                                                            "extra_facts": {"yolo": "\u0000fomo",
                                                                            "un": None}},
                                       "last_seen_report_found": True,
                                       "reports": [{"start_time": "2018-01-01 00:00:00 +0000",
                                                    "end_time": "2018-01-01 00:01:00 +0000",
                                                    "basename": "report2018",
                                                    "run_type": "auto",
                                                    "sha1sum": 40 * "0",
                                                    "events": [("2021-11-15T14:47:37Z",
                                                                {"name": "YoloApp",
                                                                 "display_name": "Yolo App",
                                                                 "version": "1.2.3",
                                                                 "status": 0,
                                                                 "type": "install"})]}]},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertEqual(response.status_code, 200)

        # check reference = serial number
        ms = MachineSnapshot.objects.current().get(serial_number=enrolled_machine.serial_number)
        ms2 = MachineSnapshot.objects.current().get(reference=enrolled_machine.serial_number)
        self.assertEqual(ms, ms2)

        # check computer name
        self.assertEqual(ms.system_info.computer_name, computer_name)

        # check extra facts
        self.assertEqual(ms.extra_facts, {"yolo": "fomo"})

        # check all events linked to machine
        for call_args in post_event.call_args_list:
            event = call_args.args[0]
            self.assertEqual(event.metadata.machine_serial_number, enrolled_machine.serial_number)

        # check last event is munki event without incident updates
        last_event = post_event.call_args.args[0]
        self.assertIsInstance(last_event, MunkiInstallEvent)
        self.assertEqual(len(last_event.metadata.incident_updates), 0)

        # check managed installs
        self.assertEqual(mi_qs.count(), 1)
        mi = mi_qs.first()
        self.assertEqual(mi.name, "YoloApp")
        self.assertEqual(mi.installed_version, "1.2.3")
        self.assertEqual(mi.installed_at, datetime(2021, 11, 15, 14, 47, 37))
        self.assertFalse(mi.reinstall)
        self.assertIsNone(mi.failed_at)
        self.assertIsNone(mi.failed_version)

        # post job with OK install, 1 hour later, but last seen report not found
        response = self._post_as_json(reverse("munki:post_job"),
                                      {"machine_snapshot": {"serial_number": enrolled_machine.serial_number,
                                                            "system_info": {"computer_name": computer_name},
                                                            "extra_facts": {"yolo": "\u0000fomo",
                                                                            "un": None}},
                                       "last_seen_report_found": False,
                                       "reports": [{"start_time": "2018-01-01 00:00:00 +0000",
                                                    "end_time": "2018-01-01 00:01:00 +0000",
                                                    "basename": "report2018",
                                                    "run_type": "auto",
                                                    "sha1sum": 40 * "0",
                                                    "events": [("2021-11-15T15:47:37Z",
                                                                {"name": "YoloApp",
                                                                 "display_name": "Yolo App",
                                                                 "version": "1.2.3",
                                                                 "status": 0,
                                                                 "type": "install"})]}]},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertEqual(response.status_code, 200)

        # check managed installs
        self.assertEqual(mi_qs.count(), 1)
        mi = mi_qs.first()
        self.assertEqual(mi.name, "YoloApp")
        self.assertEqual(mi.installed_version, "1.2.3")
        self.assertEqual(mi.installed_at, datetime(2021, 11, 15, 15, 47, 37))  # new install 1 hour later
        self.assertFalse(mi.reinstall)  # no reinstall, even if same PkgInfo, because last seen report found false
        self.assertIsNone(mi.failed_at)
        self.assertIsNone(mi.failed_version)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_job_script_check_results(self, post_event):
        enrolled_machine = self._make_enrolled_machine()
        sc = force_script_check()
        start_dt = datetime.utcnow()
        machine_status_qs = MachineStatus.objects.filter(serial_number=enrolled_machine.serial_number)
        # no MachineStatus yet
        self.assertEqual(machine_status_qs.count(), 0)

        # post job with 1 script check result
        response = self._post_as_json(reverse("munki:post_job"),
                                      {"machine_snapshot": {"serial_number": enrolled_machine.serial_number,
                                                            "system_info": {"computer_name": get_random_string(12)}},
                                       "reports": [],
                                       "script_check_results": [{
                                           "pk": sc.pk,
                                           "version": sc.compliance_check.version,
                                           "status": 0,
                                           "time": 0.1
                                        }]},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertEqual(response.status_code, 200)

        # check all events
        status_updated_event = None
        for call_args in post_event.call_args_list:
            event = call_args.args[0]
            if isinstance(event, MunkiScriptCheckStatusUpdated):
                status_updated_event = event
            # all events linked to the machine
            self.assertEqual(event.metadata.machine_serial_number, enrolled_machine.serial_number)

        # check MunkiScriptCheckStatusUpdated event
        self.assertEqual(
            status_updated_event.payload,
            {"pk": sc.compliance_check.pk,
             "model": "MunkiScriptCheck",
             "name": sc.compliance_check.name,
             "description": "",
             "version": 1,
             "munki_script_check": {"pk": sc.pk},
             "status": "OK"}
        )
        status_updated_event_metadata = status_updated_event.metadata.serialize()
        self.assertEqual(
            status_updated_event_metadata["objects"],
            {"compliance_check": [str(sc.compliance_check.pk)],
             "munki_script_check": [str(sc.pk)]}
        )

        # check MunkiState
        munki_state = MunkiState.objects.get(machine_serial_number=enrolled_machine.serial_number)
        self.assertTrue(munki_state.last_script_checks_run > start_dt)

        # check MachineStatus
        self.assertEqual(machine_status_qs.count(), 1)
        machine_status = machine_status_qs.first()
        self.assertEqual(machine_status.status, 0)
        self.assertEqual(machine_status.compliance_check, sc.compliance_check)
