from datetime import datetime
import json
from unittest.mock import patch
import uuid
from django.db.models import F
from django.urls import reverse
from django.test import TestCase
from django.urls import NoReverseMatch
from django.utils.crypto import get_random_string
from server.urls import build_urlpatterns_for_zentral_apps
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret, File, MachineSnapshot, MetaBusinessUnit
from zentral.contrib.santa.events import SantaEnrollmentEvent, SantaEventEvent, SantaPreflightEvent
from zentral.contrib.santa.models import (Bundle, Configuration, EnrolledMachine, Enrollment,
                                          MachineRule, Rule, Target, TargetCounter)
from zentral.core.incidents.models import Severity
from .utils import new_cdhash, new_sha256, new_signing_id_identifier, new_team_id


class SantaAPIViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.configuration = Configuration.objects.create(name=get_random_string(256))
        cls.configuration2 = Configuration.objects.create(name=get_random_string(256))
        cls.meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=cls.meta_business_unit)
        cls.enrollment = Enrollment.objects.create(configuration=cls.configuration,
                                                   secret=cls.enrollment_secret)
        cls.enrollment_secret2 = EnrollmentSecret.objects.create(meta_business_unit=cls.meta_business_unit)
        cls.enrollment2 = Enrollment.objects.create(configuration=cls.configuration2,
                                                    secret=cls.enrollment_secret2)
        cls.machine_serial_number = get_random_string(64)
        cls.enrolled_machine = EnrolledMachine.objects.create(enrollment=cls.enrollment,
                                                              hardware_uuid=uuid.uuid4(),
                                                              serial_number=cls.machine_serial_number,
                                                              client_mode=Configuration.MONITOR_MODE,
                                                              santa_version="2022.7")
        cls.business_unit = cls.meta_business_unit.create_enrollment_business_unit()

    def post_as_json(
        self,
        url_name, hardware_uuid, data,
        enrollment_secret=None,
    ):
        url_args = [hardware_uuid]
        secret = enrollment_secret or self.enrollment_secret.secret
        headers = {"Zentral-Authorization": f"Bearer {secret}"}
        url = reverse(f"santa_public:{url_name}", args=url_args)
        return self.client.post(url,
                                json.dumps(data),
                                content_type="application/json",
                                headers=headers)

    # preflight

    def _get_preflight_data(self, version=None, enrolled=False, legacy=False):
        if version is None:
            version = datetime.utcnow().strftime("%Y.2")
        if enrolled:
            serial_number = self.machine_serial_number
            hardware_uuid = self.enrolled_machine.hardware_uuid
        else:
            serial_number = get_random_string(12)
            hardware_uuid = uuid.uuid4()
        data = {
            "os_build": "20C69",
            "santa_version": version,
            "hostname": "hostname",
            "os_version": "11.1",
            "client_mode": "LOCKDOWN",
            "serial_number": serial_number,
            "machine_id": str(hardware_uuid),
            "primary_user": "mark.torpedo@example.com",
            "binary_rule_count": 0,
            "cdhash_rule_count": 0,
            "certificate_rule_count": 0,
            "compiler_rule_count": 0,
            "signingid_rule_count": 0,
            "teamid_rule_count": 0,
            "transitive_rule_count": 0,
        }
        if legacy:
            # pre 2024.6
            del data["machine_id"]
            data["serial_num"] = data.pop("serial_number")
        return data, serial_number, hardware_uuid

    def test_preflight_bad_auth_header_structure(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        response = self.client.post(reverse("santa_public:preflight", args=(hardware_uuid,)),
                                    data=data,
                                    content_type="application/json",
                                    headers={"Zentral-Authorization": "nobearer"})
        self.assertEqual(response.status_code, 401)

    def test_preflight_bad_auth_header_scheme(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        response = self.client.post(reverse("santa_public:preflight", args=(hardware_uuid,)),
                                    data=data,
                                    content_type="application/json",
                                    headers={"Zentral-Authorization": f"Token {self.enrollment_secret.secret}"})
        self.assertEqual(response.status_code, 401)

    def test_preflight_bad_secret(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        response = self.client.post(reverse("santa_public:preflight", args=(hardware_uuid,)),
                                    data=data,
                                    content_type="application/json",
                                    headers={"Zentral-Authorization": "Bearer bad_secret"})
        self.assertEqual(response.status_code, 403)

    def test_preflight_missing_serial_num(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        data.pop("serial_number")
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 400)

    def test_preflight_no_mtls(self):
        self.configuration.client_certificate_auth = True
        self.configuration.save()
        data, serial_number, hardware_uuid = self._get_preflight_data()
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 403)

    def test_preflight_no_auth(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        response = self.client.post(reverse("santa_public:preflight", args=(hardware_uuid,)))
        self.assertEqual(response.status_code, 401)

    def test_preflight_bad_authorization_header_scheme(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        response = self.client.post(reverse("santa_public:preflight", args=(hardware_uuid,)),
                                    headers={"Authorization": f"Token {self.enrollment_secret.secret}"})
        self.assertEqual(response.status_code, 401)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_preflight(self, post_event):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        for idx, key in enumerate(("binary_rule_count",
                                   "cdhash_rule_count",
                                   "certificate_rule_count",
                                   "compiler_rule_count",
                                   "signingid_rule_count",
                                   "teamid_rule_count",
                                   "transitive_rule_count")):
            data[key] = idx + 1

        # MONITOR mode
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["client_mode"], Configuration.PREFLIGHT_MONITOR_MODE)
        self.assertEqual(json_response["full_sync_interval"], Configuration.DEFAULT_FULL_SYNC_INTERVAL)
        self.assertEqual(json_response["sync_type"], "clean")
        self.assertTrue(json_response["blocked_path_regex"].startswith("NON_MATCHING_PLACEHOLDER_"))
        self.assertTrue(json_response["allowed_path_regex"].startswith("NON_MATCHING_PLACEHOLDER_"))

        # enrollment event
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 5)  # enrollment_secret_verification, santa_enrollment + 3 other ones
        enrollment_event = events[1]
        self.assertIsInstance(enrollment_event, SantaEnrollmentEvent)
        self.assertEqual(enrollment_event.metadata.machine_serial_number, serial_number)
        self.assertEqual(enrollment_event.payload["action"], "enrollment")

        # Enrolled machine
        enrolled_machine = EnrolledMachine.objects.get(enrollment=self.enrollment, hardware_uuid=hardware_uuid)
        self.assertEqual(enrolled_machine.serial_number, serial_number)
        self.assertEqual(enrolled_machine.primary_user, data["primary_user"])
        self.assertEqual(enrolled_machine.santa_version, data["santa_version"])
        self.assertEqual(enrolled_machine.client_mode, Configuration.LOCKDOWN_MODE)
        self.assertEqual(enrolled_machine.binary_rule_count, 1)
        self.assertEqual(enrolled_machine.cdhash_rule_count, 2)
        self.assertEqual(enrolled_machine.certificate_rule_count, 3)
        self.assertEqual(enrolled_machine.compiler_rule_count, 4)
        self.assertEqual(enrolled_machine.signingid_rule_count, 5)
        self.assertEqual(enrolled_machine.teamid_rule_count, 6)
        self.assertEqual(enrolled_machine.transitive_rule_count, 7)

        # LOCKDOWN mode
        Configuration.objects.update(client_mode=Configuration.LOCKDOWN_MODE)
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["client_mode"], Configuration.PREFLIGHT_LOCKDOWN_MODE)
        Configuration.objects.update(client_mode=Configuration.MONITOR_MODE)

        # Machine snapshot
        ms = MachineSnapshot.objects.get(serial_number=serial_number)
        self.assertEqual(ms.source.name, "Santa")
        self.assertIsNone(ms.system_info.hardware_model)

    def test_legacy_preflight(self):
        data, serial_number, hardware_uuid = self._get_preflight_data(legacy=True)
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["client_mode"], Configuration.PREFLIGHT_MONITOR_MODE)
        self.assertEqual(json_response["full_sync_interval"], Configuration.DEFAULT_FULL_SYNC_INTERVAL)
        self.assertEqual(json_response["sync_type"], "clean")
        self.assertTrue(json_response["blocked_path_regex"].startswith("NON_MATCHING_PLACEHOLDER_"))
        self.assertTrue(json_response["allowed_path_regex"].startswith("NON_MATCHING_PLACEHOLDER_"))

    def test_deprecated_preflight(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        url = reverse("santa_public:deprecated_preflight", args=(self.enrollment_secret.secret, hardware_uuid))
        response = self.client.post(url, data=data, content_type="application/json")
        self.assertEqual(response.status_code, 200)

    def test_deprecated_preflight_bad_enrollment_secret(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        url = reverse("santa_public:deprecated_preflight", args=("bad_secret", hardware_uuid))
        response = self.client.post(url, data=data, content_type="application/json")
        self.assertEqual(response.status_code, 403)

    def test_preflight_default_usb_options(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertFalse(json_response["block_usb_mount"])
        self.assertEqual(json_response["remount_usb_mode"], [])

    def test_preflight_remount_usb_options(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        Configuration.objects.update(block_usb_mount=True, remount_usb_mode=["noexec", "rdonly"])
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertTrue(json_response["block_usb_mount"])
        self.assertEqual(json_response["remount_usb_mode"], ["noexec", "rdonly"])

    def test_preflight_model_identifier(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        data["model_identifier"] = "Macmini9,1"
        self.post_as_json("preflight", hardware_uuid, data)

        # Machine snapshot
        ms = MachineSnapshot.objects.get(serial_number=serial_number)
        self.assertEqual(ms.source.name, "Santa")
        self.assertEqual(ms.system_info.hardware_model, data["model_identifier"])

    def test_preflight_missing_client_mode(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        del data["client_mode"]

        # MONITOR mode
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["client_mode"], Configuration.PREFLIGHT_MONITOR_MODE)

        # Enrolled machine
        enrolled_machine = EnrolledMachine.objects.get(enrollment=self.enrollment, hardware_uuid=hardware_uuid)
        self.assertEqual(enrolled_machine.client_mode, Configuration.MONITOR_MODE)

    def test_preflight_compiler_rule_count_overflow(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        data["compiler_rule_count"] = 27551562368811008
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)

        # Enrolled machine
        enrolled_machine = EnrolledMachine.objects.get(enrollment=self.enrollment, hardware_uuid=hardware_uuid)
        self.assertEqual(enrolled_machine.compiler_rule_count, 2147483647)

    def test_preflight_binary_rule_count_negative(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        data["binary_rule_count"] = -27551562368811008
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)

        # Enrolled machine
        enrolled_machine = EnrolledMachine.objects.get(enrollment=self.enrollment, hardware_uuid=hardware_uuid)
        self.assertEqual(enrolled_machine.binary_rule_count, 0)

    def test_preflight_enrollment_clean_sync_true(self):
        # enrollment, clean sync not requested, legacy Santa version → clean sync True
        data, serial_number, hardware_uuid = self._get_preflight_data(version="2022.1")
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertTrue(json_response["clean_sync"])

    def test_preflight_enrollment_sync_type_clean(self):
        # enrollment, clean sync not requested → sync type clean
        data, serial_number, hardware_uuid = self._get_preflight_data()
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["sync_type"], "clean")

    def test_preflight_no_enrollment_clean_sync_false(self):
        # no enrollment, clean sync not requested, legacy Santa version → clean sync False
        data, serial_number, hardware_uuid = self._get_preflight_data(version="2022.1", enrolled=True)
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertFalse(json_response["clean_sync"])

    def test_preflight_no_enrollment_sync_type_normal(self):
        # no enrollment, clean sync not requested → sync type normal
        data, serial_number, hardware_uuid = self._get_preflight_data(enrolled=True)
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["sync_type"], "normal")

    def test_preflight_no_enrollment_legacy_clean_sync_requested(self):
        # no enrollment, clean sync requested, legacy Santa version → clean sync True
        data, serial_number, hardware_uuid = self._get_preflight_data(version="2022.1", enrolled=True)
        data["request_clean_sync"] = True
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertTrue(json_response["clean_sync"])

    def test_preflight_no_enrollment_clean_sync_requested(self):
        # no enrollment, clean sync requested → sync type clean
        data, serial_number, hardware_uuid = self._get_preflight_data(enrolled=True)
        data["request_clean_sync"] = True
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["sync_type"], "clean")

    def test_preflight_no_enrollment_no_rule_counts(self):
        # no enrollment, no rule counts, no clean sync requested → sync type clean
        data, serial_number, hardware_uuid = self._get_preflight_data(enrolled=True)
        for k in list(data.keys()):
            if k.endswith("_rule_count"):
                del data[k]
        data["request_clean_sync"] = False
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["sync_type"], "clean")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_preflight_sync_not_ok_conf_without_severity_no_incident_update(self, post_event):
        # add one synced rule
        target = Target.objects.create(type=Target.Type.BINARY, identifier=new_sha256())
        rule = Rule.objects.create(configuration=self.configuration, target=target, policy=Rule.Policy.BLOCKLIST)
        MachineRule.objects.create(
            enrolled_machine=self.enrolled_machine,
            target=target,
            policy=rule.policy,
            version=rule.version,
            cursor=None
        )
        data, serial_number, hardware_uuid = self._get_preflight_data(enrolled=True)
        data["binary_rule_count"] = 0  # sync not OK
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)
        self.enrolled_machine.refresh_from_db()
        self.assertFalse(self.enrolled_machine.sync_ok())
        self.assertIsNone(self.enrolled_machine.last_sync_ok)  # not updated
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 3)  # add machine, inventory heartbeat, santa preflight
        preflight_event = events[-1]
        self.assertIsInstance(preflight_event, SantaPreflightEvent)
        self.assertEqual(preflight_event.metadata.machine_serial_number, self.enrolled_machine.serial_number)
        self.assertEqual(len(preflight_event.metadata.incident_updates), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_preflight_sync_ok_conf_with_severity_first_time_no_incident_update(self, post_event):
        # setup the sync incidents
        self.configuration.sync_incident_severity = Severity.CRITICAL.value
        self.configuration.save()
        # add one synced rule
        target = Target.objects.create(type=Target.Type.BINARY, identifier=new_sha256())
        rule = Rule.objects.create(configuration=self.configuration, target=target, policy=Rule.Policy.BLOCKLIST)
        MachineRule.objects.create(
            enrolled_machine=self.enrolled_machine,
            target=target,
            policy=rule.policy,
            version=rule.version,
            cursor=None
        )
        data, serial_number, hardware_uuid = self._get_preflight_data(enrolled=True)
        data["binary_rule_count"] = 1
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)
        self.enrolled_machine.refresh_from_db()
        self.assertTrue(self.enrolled_machine.sync_ok())
        self.assertTrue(self.enrolled_machine.last_sync_ok)
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 3)  # add machine, inventory heartbeat, santa preflight
        preflight_event = events[-1]
        self.assertIsInstance(preflight_event, SantaPreflightEvent)
        self.assertEqual(preflight_event.metadata.machine_serial_number, self.enrolled_machine.serial_number)
        self.assertEqual(len(preflight_event.metadata.incident_updates), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_preflight_sync_ok_conf_with_severity_resolution_incident_update_none(self, post_event):
        # setup the sync incidents
        self.configuration.sync_incident_severity = Severity.CRITICAL.value
        self.configuration.save()
        # simulate sync not ok status
        self.enrolled_machine.last_sync_ok = False
        self.enrolled_machine.save()
        # add one synced rule
        target = Target.objects.create(type=Target.Type.BINARY, identifier=new_sha256())
        rule = Rule.objects.create(configuration=self.configuration, target=target, policy=Rule.Policy.BLOCKLIST)
        MachineRule.objects.create(
            enrolled_machine=self.enrolled_machine,
            target=target,
            policy=rule.policy,
            version=rule.version,
            cursor=None
        )
        data, serial_number, hardware_uuid = self._get_preflight_data(enrolled=True)
        data["binary_rule_count"] = 1
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)
        self.enrolled_machine.refresh_from_db()
        self.assertTrue(self.enrolled_machine.sync_ok())
        self.assertTrue(self.enrolled_machine.last_sync_ok)
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 3)  # add machine, inventory heartbeat, santa preflight
        preflight_event = events[-1]
        self.assertIsInstance(preflight_event, SantaPreflightEvent)
        self.assertEqual(len(preflight_event.metadata.incident_updates), 1)
        incident_update = preflight_event.metadata.incident_updates[0]
        self.assertEqual(incident_update.incident_type, "santa_sync")
        self.assertEqual(incident_update.key, {"santa_cfg_pk": self.configuration.pk})
        self.assertEqual(incident_update.severity, Severity.NONE)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_preflight_sync_not_ok_conf_with_severity_change_incident_update(self, post_event):
        # setup the sync incidents
        self.configuration.sync_incident_severity = Severity.MAJOR.value
        self.configuration.save()
        # add one synced rule
        target = Target.objects.create(type=Target.Type.BINARY, identifier=new_sha256())
        rule = Rule.objects.create(configuration=self.configuration, target=target, policy=Rule.Policy.BLOCKLIST)
        MachineRule.objects.create(
            enrolled_machine=self.enrolled_machine,
            target=target,
            policy=rule.policy,
            version=rule.version,
            cursor=None
        )
        data, serial_number, hardware_uuid = self._get_preflight_data(enrolled=True)
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)
        self.enrolled_machine.refresh_from_db()
        self.assertFalse(self.enrolled_machine.sync_ok())
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 3)  # add machine, inventory heartbeat, santa preflight
        preflight_event = events[-1]
        self.assertIsInstance(preflight_event, SantaPreflightEvent)
        self.assertEqual(len(preflight_event.metadata.incident_updates), 1)
        incident_update = preflight_event.metadata.incident_updates[0]
        self.assertEqual(incident_update.incident_type, "santa_sync")
        self.assertEqual(incident_update.key, {"santa_cfg_pk": self.configuration.pk})
        self.assertEqual(incident_update.severity, Severity.MAJOR)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_preflight_sync_not_ok_conf_with_severity_no_change_no_incident_update(self, post_event):
        # setup the sync incidents
        self.configuration.sync_incident_severity = Severity.MAJOR.value
        self.configuration.save()
        # simulate sync not ok status
        self.enrolled_machine.last_sync_ok = False
        self.enrolled_machine.save()
        # add one synced rule
        target = Target.objects.create(type=Target.Type.BINARY, identifier=new_sha256())
        rule = Rule.objects.create(configuration=self.configuration, target=target, policy=Rule.Policy.BLOCKLIST)
        MachineRule.objects.create(
            enrolled_machine=self.enrolled_machine,
            target=target,
            policy=rule.policy,
            version=rule.version,
            cursor=None
        )
        data, serial_number, hardware_uuid = self._get_preflight_data(enrolled=True)
        response = self.post_as_json("preflight", hardware_uuid, data)
        self.assertEqual(response.status_code, 200)
        self.enrolled_machine.refresh_from_db()
        self.assertFalse(self.enrolled_machine.sync_ok())
        self.assertFalse(self.enrolled_machine.last_sync_ok)
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 3)  # add machine, inventory heartbeat, santa preflight
        preflight_event = events[-1]
        self.assertIsInstance(preflight_event, SantaPreflightEvent)
        self.assertEqual(len(preflight_event.metadata.incident_updates), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_preflight_reenrollment_incident_update_none_old_config(self, post_event):
        # simulate sync not ok status
        self.enrolled_machine.last_sync_ok = False
        self.enrolled_machine.save()
        data, serial_number, hardware_uuid = self._get_preflight_data(enrolled=True)
        response = self.post_as_json("preflight", hardware_uuid, data,
                                     enrollment_secret=self.enrollment_secret2.secret)
        self.assertEqual(response.status_code, 200)
        enrolled_machine = EnrolledMachine.objects.get(serial_number=self.machine_serial_number)
        self.assertNotEqual(enrolled_machine, self.enrolled_machine)
        self.assertTrue(enrolled_machine.sync_ok())
        self.assertEqual(enrolled_machine.enrollment, self.enrollment2)
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 5)  # enrollment_secret_verification, santa_enrollment + 3 other ones
        enrollment_event = events[1]
        self.assertIsInstance(enrollment_event, SantaEnrollmentEvent)
        self.assertEqual(enrollment_event.payload["action"], "re-enrollment")
        self.assertEqual(len(enrollment_event.metadata.incident_updates), 1)
        incident_update = enrollment_event.metadata.incident_updates[0]
        self.assertEqual(incident_update.incident_type, "santa_sync")
        self.assertEqual(incident_update.key, {"santa_cfg_pk": self.configuration.pk})
        self.assertEqual(incident_update.severity, Severity.NONE)
        preflight_event = events[-1]
        self.assertIsInstance(preflight_event, SantaPreflightEvent)
        self.assertEqual(len(preflight_event.metadata.incident_updates), 0)

    # rule download

    def test_rule_download_not_enrolled(self):
        # no rules
        response = self.post_as_json("ruledownload", uuid.uuid4(), {})
        self.assertEqual(response.status_code, 403)

    def test_rule_download(self):
        # no rules
        response = self.post_as_json("ruledownload", self.enrolled_machine.hardware_uuid, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"rules": []})
        # add a rule
        target = Target.objects.create(type=Target.Type.BINARY, identifier=new_sha256())
        rule = Rule.objects.create(
            configuration=self.configuration,
            target=target,
            policy=Rule.Policy.BLOCKLIST,
        )
        response = self.post_as_json("ruledownload", self.enrolled_machine.hardware_uuid, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.Type.BINARY,
              "identifier": target.identifier,
              "policy": "BLOCKLIST"}]
        )
        # rule not confirmed, same rule
        response = self.post_as_json("ruledownload", self.enrolled_machine.hardware_uuid, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.Type.BINARY,
              "identifier": target.identifier,
              "policy": "BLOCKLIST"}]
        )
        # rule acknowleged, no rules
        response = self.post_as_json("ruledownload", self.enrolled_machine.hardware_uuid,
                                     {"cursor": json_response["cursor"]})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"rules": []})
        # updated rule, rule
        rule.custom_msg = "BAD LUCK"
        rule.version = F("version") + 1
        rule.save()
        response = self.post_as_json("ruledownload", self.enrolled_machine.hardware_uuid, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.Type.BINARY,
              "identifier": target.identifier,
              "policy": "BLOCKLIST",
              "custom_msg": rule.custom_msg}]
        )
        # updated rule not acknowleged, same updated rule
        response = self.post_as_json("ruledownload", self.enrolled_machine.hardware_uuid, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.Type.BINARY,
              "identifier": target.identifier,
              "policy": "BLOCKLIST",
              "custom_msg": rule.custom_msg}]
        )
        # updated rule acknowleged, no rules
        response = self.post_as_json("ruledownload", self.enrolled_machine.hardware_uuid,
                                     {"cursor": json_response["cursor"]})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"rules": []})
        # rule out of scope, remove rule
        rule.serial_numbers = [get_random_string(12)]
        rule.save()
        response = self.post_as_json("ruledownload", self.enrolled_machine.hardware_uuid, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.Type.BINARY,
              "identifier": target.identifier,
              "policy": "REMOVE"}]
        )
        # remove rule not confirm, same remove rule
        response = self.post_as_json("ruledownload", self.enrolled_machine.hardware_uuid, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.Type.BINARY,
              "identifier": target.identifier,
              "policy": "REMOVE"}]
        )
        # rule out of scope with excluded serial number, same remove rule
        rule.serial_numbers = []
        rule.excluded_serial_numbers = [self.enrolled_machine.serial_number]
        rule.save()
        response = self.post_as_json("ruledownload", self.enrolled_machine.hardware_uuid, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.Type.BINARY,
              "identifier": target.identifier,
              "policy": "REMOVE"}]
        )
        # remove rule acknowleged, no rules
        response = self.post_as_json("ruledownload", self.enrolled_machine.hardware_uuid,
                                     {"cursor": json_response["cursor"]})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"rules": []})
        # rule again in scope by removing excluded serial number, we get the rule
        rule.excluded_serial_numbers = [get_random_string(15)]
        rule.save()
        response = self.post_as_json("ruledownload", self.enrolled_machine.hardware_uuid, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.Type.BINARY,
              "identifier": target.identifier,
              "policy": "BLOCKLIST",
              "custom_msg": rule.custom_msg}]
        )
        # rule again in scope acknowleged, no rules
        response = self.post_as_json("ruledownload", self.enrolled_machine.hardware_uuid,
                                     {"cursor": json_response["cursor"]})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"rules": []})

    def test_cel_rule_download(self):
        # add a CEL rule
        target = Target.objects.create(type=Target.Type.BINARY, identifier=new_sha256())
        Rule.objects.create(
            configuration=self.configuration,
            target=target,
            policy=Rule.Policy.CEL,
            cel_expr="target.signing_time >= timestamp('2025-05-31T00:00:00Z')",
        )
        # No rules with CEL policies for older Santa agents
        self.assertTrue(self.enrolled_machine.get_comparable_santa_version() < (2025, 6))
        response = self.post_as_json("ruledownload", self.enrolled_machine.hardware_uuid, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["rules"], [])
        # Rules with CEL policies for Santa agent >= 2025.6
        enrolled_machine = EnrolledMachine.objects.create(enrollment=self.enrollment,
                                                          hardware_uuid=uuid.uuid4(),
                                                          serial_number=get_random_string(12),
                                                          client_mode=Configuration.MONITOR_MODE,
                                                          santa_version="2025.6")
        self.assertTrue(enrolled_machine.get_comparable_santa_version() >= (2025, 6))
        response = self.post_as_json("ruledownload", enrolled_machine.hardware_uuid, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.Type.BINARY,
              "identifier": target.identifier,
              "policy": "CEL",
              "cel_expr": "target.signing_time >= timestamp('2025-05-31T00:00:00Z')"}]
        )

    def test_deprecated_rule_download(self):
        # no rules
        url = reverse("santa_public:deprecated_ruledownload", args=(self.enrollment_secret.secret,
                                                                    self.enrolled_machine.hardware_uuid))
        response = self.client.post(url, data={}, content_type="application/json")
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"rules": []})

    # event upload

    def test_eventupload_not_enrolled(self):
        response = self.post_as_json("eventupload", uuid.uuid4(), {})
        self.assertEqual(response.status_code, 403)

    def test_eventupload_cdhash_signing_id_team_id(self):
        team_id = new_team_id()
        event_d = {
            'cdhash': new_cdhash(),
            'current_sessions': [],
            'decision': 'BLOCK_UNKNOWN',
            'executing_user': 'root',
            'execution_time': 2242783327.585212,
            'file_bundle_id': 'servicecontroller:com.apple.stomp.transcoderx',
            'file_bundle_name': 'CompressorTranscoderX',
            'file_bundle_path': ('/Library/Frameworks/Compressor.framework/'
                                 'Versions/A/Resources/CompressorTranscoderX.bundle'),
            'file_bundle_version': '3.5.3',
            'file_bundle_version_string': '3.5.3',
            'file_name': 'compressord',
            'file_path': ('/Library/Frameworks/Compressor.framework/'
                          'Versions/A/Resources/CompressorTranscoderX.bundle/Contents/MacOS'),
            'file_sha256': new_sha256(),
            'logged_in_users': [],
            'parent_name': 'launchd',
            'pid': 95,
            'ppid': 1,
            'quarantine_timestamp': 0,
            'signing_id': new_signing_id_identifier(),
            'team_id': team_id,
            'signing_chain': [{'cn': 'Software Signing',
                               'ou': team_id,
                               'org': 'Apple Inc.',
                               'sha256': new_sha256(),
                               'valid_from': 1172268176,
                               'valid_until': 1421272976},
                              {'cn': 'Apple Code Signing Certification Authority',
                               'org': 'Apple Inc.',
                               'ou': 'Apple Certification Authority',
                               'sha256': '3afa0bf5027fd0532f436b39363a680aefd6baf7bf6a4f97f17be2937b84b150',
                               'valid_from': 1171487959,
                               'valid_until': 1423948759},
                              {'cn': 'Apple Root CA',
                               'org': 'Apple Inc.',
                               'ou': 'Apple Certification Authority',
                               'sha256': 'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024',
                               'valid_from': 1146001236,
                               'valid_until': 2054670036}]
        }
        response = self.post_as_json("eventupload", self.enrolled_machine.hardware_uuid, {"events": [event_d]})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {})
        self.assertEqual(Bundle.objects.count(), 0)
        f = File.objects.get(sha_256=event_d["file_sha256"])
        self.assertEqual(f.cdhash, event_d["cdhash"])
        self.assertEqual(f.signing_id, event_d["signing_id"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_eventupload_without_bundle(self, post_event):
        event_d = {
            'current_sessions': [],
            'decision': 'ALLOW_UNKNOWN',
            'executing_user': 'root',
            'execution_time': 2242783327.585212,
            'file_bundle_id': 'servicecontroller:com.apple.stomp.transcoderx',
            'file_bundle_name': 'CompressorTranscoderX',
            'file_bundle_path': ('/Library/Frameworks/Compressor.framework/'
                                 'Versions/A/Resources/CompressorTranscoderX.bundle'),
            'file_bundle_version': '3.5.3',
            'file_bundle_version_string': '3.5.3',
            'file_name': 'compressord',
            'file_path': ('/Library/Frameworks/Compressor.framework/'
                          'Versions/A/Resources/CompressorTranscoderX.bundle/Contents/MacOS'),
            'file_sha256': new_sha256(),
            'logged_in_users': [],
            'parent_name': 'launchd',
            'pid': 95,
            'ppid': 1,
            'quarantine_timestamp': 0,
            'signing_chain': [{'cn': 'Software Signing',
                               'ou': new_team_id(),
                               'org': 'Apple Inc.',
                               'sha256': new_sha256(),
                               'valid_from': 1172268176,
                               'valid_until': 1421272976},
                              {'cn': 'Apple Code Signing Certification Authority',
                               'org': 'Apple Inc.',
                               'ou': 'Apple Certification Authority',
                               'sha256': '3afa0bf5027fd0532f436b39363a680aefd6baf7bf6a4f97f17be2937b84b150',
                               'valid_from': 1171487959,
                               'valid_until': 1423948759},
                              {'cn': 'Apple Root CA',
                               'org': 'Apple Inc.',
                               'ou': 'Apple Certification Authority',
                               'sha256': 'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024',
                               'valid_from': 1146001236,
                               'valid_until': 2054670036}]
        }
        self.assertEqual(Target.objects.all().count(), 0)
        target = Target.objects.create(
            type=Target.Type.CERTIFICATE,
            identifier=event_d["signing_chain"][1]["sha256"],
        )
        TargetCounter.objects.create(
            target=target,
            configuration=self.configuration,
            blocked_count=3,
            collected_count=2,
            executed_count=1,
        )
        response = self.post_as_json("eventupload", self.enrolled_machine.hardware_uuid, {"events": [event_d]})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {})
        self.assertEqual(Bundle.objects.count(), 0)
        f = File.objects.get(sha_256=event_d["file_sha256"])
        self.assertEqual(f.signed_by.sha_256, event_d["signing_chain"][0]["sha256"])
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        event = events[0]
        self.assertIsInstance(event, SantaEventEvent)
        # default to flattened signing chain
        for i, cert in enumerate(event_d["signing_chain"]):
            self.assertEqual(event.payload[f"signing_cert_{i}"], cert)
        self.assertNotIn("signing_chain", event.payload)
        self.assertEqual(Target.objects.all().count(), 4)
        for target_type, target_identifier, b_count, c_count, e_count in (
            (Target.Type.BINARY, event_d["file_sha256"], 0, 0, 1),
            (Target.Type.CERTIFICATE, event_d["signing_chain"][0]["sha256"], 0, 0, 1),
            (Target.Type.CERTIFICATE, event_d["signing_chain"][1]["sha256"], 3, 2, 2),  # executed_count = 1 + 1
            (Target.Type.CERTIFICATE, event_d["signing_chain"][2]["sha256"], 0, 0, 1),
        ):
            self.assertTrue(
                TargetCounter.objects.filter(target__type=target_type,
                                             target__identifier=target_identifier,
                                             configuration=self.configuration,
                                             blocked_count=b_count,
                                             collected_count=c_count,
                                             executed_count=e_count).exists()
            )

    def test_deprecated_eventupload(self):
        url = reverse("santa_public:deprecated_eventupload", args=(self.enrollment_secret.secret,
                                                                   self.enrolled_machine.hardware_uuid))
        response = self.client.post(url, data={"events": []}, content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {})

    @patch("zentral.contrib.santa.events.flatten_events_signing_chain", False)
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_eventupload_with_bundle(self, post_event):
        event_d = {
            'current_sessions': [],
            'decision': 'BLOCK_UNKNOWN',
            'executing_user': 'root',
            'execution_time': 2242783327.585212,
            'file_bundle_id': 'servicecontroller:com.apple.stomp.transcoderx',
            'file_bundle_name': 'CompressorTranscoderX',
            'file_bundle_path': ('/Library/Frameworks/Compressor.framework/'
                                 'Versions/A/Resources/CompressorTranscoderX.bundle'),
            'file_bundle_version': '3.5.3',
            'file_bundle_version_string': '3.5.3',
            'file_bundle_hash': "4764c9e3305c6c749538fbfaa1704a0cb61c150453fe40f739979964361c15dd",
            'file_bundle_binary_count': 1,
            'file_name': 'compressord',
            'file_path': ('/Library/Frameworks/Compressor.framework/'
                          'Versions/A/Resources/CompressorTranscoderX.bundle/Contents/MacOS'),
            'file_sha256': new_sha256(),
            'logged_in_users': [],
            'parent_name': 'launchd',
            'pid': 95,
            'ppid': 1,
            'quarantine_timestamp': 0,
            'signing_chain': [{'cn': 'Software Signing',
                               'ou': new_team_id(),
                               'org': 'Apple Inc.',
                               'sha256': new_sha256(),
                               'valid_from': 1172268176,
                               'valid_until': 1421272976},
                              {'cn': 'Apple Code Signing Certification Authority',
                               'org': 'Apple Inc.',
                               'ou': 'Apple Certification Authority',
                               'sha256': '3afa0bf5027fd0532f436b39363a680aefd6baf7bf6a4f97f17be2937b84b150',
                               'valid_from': 1171487959,
                               'valid_until': 1423948759},
                              {'cn': 'Apple Root CA',
                               'org': 'Apple Inc.',
                               'ou': 'Apple Certification Authority',
                               'sha256': 'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024',
                               'valid_from': 1146001236,
                               'valid_until': 2054670036}]
        }
        self.assertEqual(Target.objects.all().count(), 0)
        target = Target.objects.create(
            type=Target.Type.BINARY,
            identifier=event_d["file_sha256"],
        )
        TargetCounter.objects.create(
            target=target,
            configuration=self.configuration,
            blocked_count=3,
            collected_count=2,
            executed_count=1,
        )
        response = self.post_as_json("eventupload", self.enrolled_machine.hardware_uuid, {"events": [event_d]})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"event_upload_bundle_binaries": [event_d["file_bundle_hash"]]})
        b = Bundle.objects.get(target__type=Target.Type.BUNDLE, target__identifier=event_d["file_bundle_hash"])
        self.assertIsNone(b.uploaded_at)
        self.assertEqual(b.bundle_id, event_d["file_bundle_id"])
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, SantaEventEvent)
        self.assertEqual(event.payload["signing_chain"], event_d["signing_chain"])
        self.assertEqual(Target.objects.all().count(), 5)
        for target_type, target_identifier, b_count, c_count, e_count in (
            (Target.Type.BINARY, event_d["file_sha256"], 4, 2, 1),
            (Target.Type.BUNDLE, event_d["file_bundle_hash"], 1, 0, 0),
            (Target.Type.CERTIFICATE, event_d["signing_chain"][0]["sha256"], 1, 0, 0),
            (Target.Type.CERTIFICATE, event_d["signing_chain"][1]["sha256"], 1, 0, 0),
            (Target.Type.CERTIFICATE, event_d["signing_chain"][2]["sha256"], 1, 0, 0),
        ):
            self.assertTrue(
                TargetCounter.objects.filter(target__type=target_type,
                                             target__identifier=target_identifier,
                                             configuration=self.configuration,
                                             blocked_count=b_count,
                                             collected_count=c_count,
                                             executed_count=e_count).exists()
            )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_eventupload_bundle_binary(self, post_event):
        cdhash = new_cdhash()
        event_d = {
            'cdhash': cdhash,
            'current_sessions': [],
            'decision': 'BUNDLE_BINARY',
            'executing_user': 'root',
            'execution_time': 2242783327.585212,
            'file_bundle_id': 'servicecontroller:com.apple.stomp.transcoderx',
            'file_bundle_name': 'CompressorTranscoderX',
            'file_bundle_path': ('/Library/Frameworks/Compressor.framework/'
                                 'Versions/A/Resources/CompressorTranscoderX.bundle'),
            'file_bundle_version': '3.5.3',
            'file_bundle_version_string': '3.5.3',
            'file_bundle_hash': "4764c9e3305c6c749538fbfaa1704a0cb61c150453fe40f739979964361c15dd",
            'file_bundle_binary_count': 1,
            'file_name': 'compressord',
            'file_path': ('/Library/Frameworks/Compressor.framework/'
                          'Versions/A/Resources/CompressorTranscoderX.bundle/Contents/MacOS'),
            'file_sha256': new_sha256(),
            'logged_in_users': [],
            'parent_name': 'launchd',
            'pid': 95,
            'ppid': 1,
            'quarantine_timestamp': 0,
            'team_id': new_team_id(),
            'signing_id': new_signing_id_identifier(),
            'signing_chain': [{'cn': 'Software Signing',
                               'ou': new_team_id(),
                               'org': 'Apple Inc.',
                               'sha256': new_sha256(),
                               'valid_from': 1172268176,
                               'valid_until': 1421272976},
                              {'cn': 'Apple Code Signing Certification Authority',
                               'org': 'Apple Inc.',
                               'ou': 'Apple Certification Authority',
                               'sha256': '3afa0bf5027fd0532f436b39363a680aefd6baf7bf6a4f97f17be2937b84b150',
                               'valid_from': 1171487959,
                               'valid_until': 1423948759},
                              {'cn': 'Apple Root CA',
                               'org': 'Apple Inc.',
                               'ou': 'Apple Certification Authority',
                               'sha256': 'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024',
                               'valid_from': 1146001236,
                               'valid_until': 2054670036}]
        }
        t, _ = Target.objects.get_or_create(type=Target.Type.BUNDLE,
                                            identifier=event_d["file_bundle_hash"])
        b, _ = Bundle.objects.update_or_create(
            target=t,
            defaults={"binary_count": event_d["file_bundle_binary_count"]}
        )
        file_qs = File.objects.filter(cdhash=cdhash)
        self.assertEqual(file_qs.count(), 0)
        response = self.post_as_json("eventupload", self.enrolled_machine.hardware_uuid, {"events": [event_d]})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {})
        b.refresh_from_db()
        self.assertIsNotNone(b.uploaded_at)
        self.assertEqual(
            list(b.binary_targets.all()),
            [Target.objects.get(type=Target.Type.BINARY, identifier=event_d["file_sha256"])]
        )
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 0)
        self.assertEqual(file_qs.count(), 1)
        file = file_qs.first()
        self.assertEqual(file.signing_id, event_d["signing_id"])
        self.assertEqual(Target.objects.all().count(), 9)
        for target_type, target_identifier, b_count, c_count, e_count in (
            (Target.Type.BINARY, event_d["file_sha256"], 0, 1, 0),
            (Target.Type.CDHASH, event_d["cdhash"], 0, 1, 0),
            (Target.Type.SIGNING_ID, event_d["signing_id"], 0, 1, 0),
            (Target.Type.TEAM_ID, event_d["team_id"], 0, 1, 0),
            (Target.Type.CERTIFICATE, event_d["signing_chain"][0]["sha256"], 0, 1, 0),
            (Target.Type.CERTIFICATE, event_d["signing_chain"][1]["sha256"], 0, 1, 0),
            (Target.Type.CERTIFICATE, event_d["signing_chain"][2]["sha256"], 0, 1, 0),
        ):
            self.assertTrue(
                TargetCounter.objects.filter(target__type=target_type,
                                             target__identifier=target_identifier,
                                             configuration=self.configuration,
                                             blocked_count=b_count,
                                             collected_count=c_count,
                                             executed_count=e_count).exists()
            )

    # postflight

    def test_rule_postflight_not_enrolled(self):
        response = self.post_as_json("postflight", uuid.uuid4(), {})
        self.assertEqual(response.status_code, 403)

    def test_postflight(self):
        response = self.post_as_json("postflight", self.enrolled_machine.hardware_uuid, {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {})

    def test_deprecated_postflight(self):
        url = reverse("santa_public:deprecated_postflight", args=(self.enrollment_secret.secret,
                                                                  self.enrolled_machine.hardware_uuid))
        response = self.client.post(url, data={}, content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {})

    def test_legacy_public_urls_are_disabled_on_tests(self):
        hardware_uuid = uuid.uuid4()
        routes = ['preflight', 'ruledownload', 'eventupload', 'postflight']

        for route in routes:
            with self.assertRaises(NoReverseMatch):
                reverse(f"santa_public_legacy:{route}", args=(self.enrollment_secret.secret, hardware_uuid))
            self.assertIsNotNone(reverse(f"santa_public:deprecated_{route}",
                                         args=(self.enrollment_secret.secret, hardware_uuid)))

    def test_mount_legacy_public_endpoints_flag_is_working(self):
        hardware_uuid = uuid.uuid4()
        routes = ['preflight', 'ruledownload', 'eventupload', 'postflight']

        santa_conf = settings._collection["apps"]._collection["zentral.contrib.santa"]
        santa_conf._collection["mount_legacy_public_endpoints"] = True
        urlpatterns_w_legacy = tuple(build_urlpatterns_for_zentral_apps())
        santa_conf._collection["mount_legacy_public_endpoints"] = False
        urlpatterns_wo_legacy = tuple(build_urlpatterns_for_zentral_apps())

        for route in routes:
            self.assertEqual(
                reverse(f"santa_public:deprecated_{route}",
                        urlconf=urlpatterns_w_legacy,
                        args=(self.enrollment_secret.secret, hardware_uuid)
                        ),
                "/public" + reverse(f"santa_public_legacy:deprecated_{route}",
                                    urlconf=urlpatterns_w_legacy,
                                    args=(self.enrollment_secret.secret, hardware_uuid)
                                    )
            )
            with self.assertRaises(NoReverseMatch):
                reverse(f"santa_public_legacy:deprecated_{route}",
                        urlconf=urlpatterns_wo_legacy,
                        args=(self.enrollment_secret.secret, hardware_uuid)
                        )
