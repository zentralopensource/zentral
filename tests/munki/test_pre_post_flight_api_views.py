from datetime import datetime
import json
from unittest.mock import patch
import uuid
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret, MachineSnapshot, MetaBusinessUnit, Tag, MachineTag
from zentral.contrib.munki.events import MunkiInstallEvent, MunkiInstallFailedEvent
from zentral.contrib.munki.incidents import IncidentUpdate, MunkiInstallFailedIncident
from zentral.contrib.munki.models import Configuration, EnrolledMachine, Enrollment, ManagedInstall
from zentral.core.incidents.models import Incident, MachineIncident, Severity, Status


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

    # job details

    def test_job_details_missing_auth_header_err(self):
        response = self._post_as_json(reverse("munki:job_details"), {})
        self.assertContains(response, "Missing or empty Authorization header", status_code=403)

    def test_job_details_wrong_auth_token_err(self):
        response = self._post_as_json(reverse("munki:job_details"), {},
                                      HTTP_AUTHORIZATION=get_random_string(23))
        self.assertContains(response, "Wrong authorization token", status_code=403)

    def test_job_details_enrolled_machine_does_not_exist_err(self):
        response = self._post_as_json(reverse("munki:job_details"), {},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(get_random_string(34)))
        self.assertContains(response, "Enrolled machine does not exist", status_code=403)

    def test_job_details_missing_serial_number_err(self):
        enrolled_machine = self._make_enrolled_machine()
        response = self._post_as_json(reverse("munki:job_details"), {},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertContains(response,
                            f"No reported machine serial number. Request SN {enrolled_machine.serial_number}.",
                            status_code=403)

    def test_job_details_machine_conflict_err(self):
        enrolled_machine = self._make_enrolled_machine()
        data_sn = get_random_string(9)
        response = self._post_as_json(reverse("munki:job_details"),
                                      {"machine_serial_number": data_sn},
                                      HTTP_AUTHORIZATION="MunkiEnrolledMachine {}".format(enrolled_machine.token))
        self.assertContains(response,
                            (f"Zentral postflight reported SN {data_sn} "
                             f"different from enrollment SN {enrolled_machine.serial_number}"),
                            status_code=403)

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
        self.assertContains(response, "different from enrollment SN", status_code=403)

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
