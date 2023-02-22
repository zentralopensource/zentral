import json
from unittest.mock import patch
import uuid
from django.db.models import F
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret, File, MachineSnapshot, MetaBusinessUnit
from zentral.contrib.santa.events import SantaEnrollmentEvent, SantaEventEvent, SantaPreflightEvent
from zentral.contrib.santa.models import (Bundle, Configuration, EnrolledMachine, Enrollment,
                                          MachineRule, Rule, Target)
from zentral.core.incidents.models import Severity


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
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

    def post_as_json(self, url, data):
        return self.client.post(url,
                                json.dumps(data),
                                content_type="application/json")

    # preflight

    def _get_preflight_data(self, enrolled=False):
        if enrolled:
            serial_number = self.machine_serial_number
            hardware_uuid = self.enrolled_machine.hardware_uuid
        else:
            serial_number = get_random_string(12)
            hardware_uuid = uuid.uuid4()
        data = {
            "os_build": "20C69",
            "santa_version": "2022.1",
            "hostname": "hostname",
            "transitive_rule_count": 0,
            "os_version": "11.1",
            "certificate_rule_count": 0,
            "client_mode": "LOCKDOWN",
            "serial_num": serial_number,
            "binary_rule_count": 0,
            "primary_user": "mark.torpedo@example.com",
            "compiler_rule_count": 0,
            "teamid_rule_count": 0
        }
        return data, serial_number, hardware_uuid

    def test_preflight_bad_secret(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        url = reverse("santa_public:preflight", args=(get_random_string(12), hardware_uuid))
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 403)

    def test_preflight_missing_serial_num(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        data.pop("serial_num")
        url = reverse("santa_public:preflight", args=(self.enrollment_secret.secret, hardware_uuid))
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 400)

    def test_preflight_no_mtls(self):
        self.configuration.client_certificate_auth = True
        self.configuration.save()
        data, serial_number, hardware_uuid = self._get_preflight_data()
        url = reverse("santa_public:preflight", args=(self.enrollment_secret.secret, hardware_uuid))
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_preflight(self, post_event):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        data["binary_rule_count"] = 17
        url = reverse("santa_public:preflight", args=(self.enrollment_secret.secret, hardware_uuid))

        # MONITOR mode
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["client_mode"], Configuration.PREFLIGHT_MONITOR_MODE)
        self.assertEqual(json_response["full_sync_interval"], Configuration.DEFAULT_FULL_SYNC_INTERVAL)
        self.assertEqual(json_response["clean_sync"], True)
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
        self.assertEqual(enrolled_machine.binary_rule_count, 17)

        # LOCKDOWN mode
        Configuration.objects.update(client_mode=Configuration.LOCKDOWN_MODE)
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["client_mode"], Configuration.PREFLIGHT_LOCKDOWN_MODE)
        Configuration.objects.update(client_mode=Configuration.MONITOR_MODE)

        # Machine snapshot
        ms = MachineSnapshot.objects.get(serial_number=serial_number)
        self.assertEqual(ms.source.name, "Santa")
        self.assertIsNone(ms.system_info.hardware_model)

    def test_preflight_default_usb_options(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        url = reverse("santa_public:preflight", args=(self.enrollment_secret.secret, hardware_uuid))
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertFalse(json_response["block_usb_mount"])
        self.assertEqual(json_response["remount_usb_mode"], [])

    def test_preflight_remount_usb_options(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        Configuration.objects.update(block_usb_mount=True, remount_usb_mode=["noexec", "rdonly"])
        url = reverse("santa_public:preflight", args=(self.enrollment_secret.secret, hardware_uuid))
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertTrue(json_response["block_usb_mount"])
        self.assertEqual(json_response["remount_usb_mode"], ["noexec", "rdonly"])

    def test_preflight_model_identifier(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        data["model_identifier"] = "Macmini9,1"
        url = reverse("santa_public:preflight", args=(self.enrollment_secret.secret, hardware_uuid))
        self.post_as_json(url, data)

        # Machine snapshot
        ms = MachineSnapshot.objects.get(serial_number=serial_number)
        self.assertEqual(ms.source.name, "Santa")
        self.assertEqual(ms.system_info.hardware_model, data["model_identifier"])

    def test_preflight_missing_client_mode(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        del data["client_mode"]
        url = reverse("santa_public:preflight", args=(self.enrollment_secret.secret, hardware_uuid))

        # MONITOR mode
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["client_mode"], Configuration.PREFLIGHT_MONITOR_MODE)

        # Enrolled machine
        enrolled_machine = EnrolledMachine.objects.get(enrollment=self.enrollment, hardware_uuid=hardware_uuid)
        self.assertEqual(enrolled_machine.client_mode, Configuration.MONITOR_MODE)

    def test_preflight_compiler_rule_count_overflow(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        data["compiler_rule_count"] = 27551562368811008
        url = reverse("santa_public:preflight", args=(self.enrollment_secret.secret, hardware_uuid))
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 200)

        # Enrolled machine
        enrolled_machine = EnrolledMachine.objects.get(enrollment=self.enrollment, hardware_uuid=hardware_uuid)
        self.assertEqual(enrolled_machine.compiler_rule_count, 2147483647)

    def test_preflight_binary_rule_count_negative(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        data["binary_rule_count"] = -27551562368811008
        url = reverse("santa_public:preflight", args=(self.enrollment_secret.secret, hardware_uuid))
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 200)

        # Enrolled machine
        enrolled_machine = EnrolledMachine.objects.get(enrollment=self.enrollment, hardware_uuid=hardware_uuid)
        self.assertEqual(enrolled_machine.binary_rule_count, 0)

    def test_preflight_enrollment_clean_sync(self):
        # enrollment, clean sync not requested → clean sync
        data, serial_number, hardware_uuid = self._get_preflight_data()
        url = reverse("santa_public:preflight", args=(self.enrollment_secret.secret, hardware_uuid))
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertTrue(json_response["clean_sync"])

    def test_preflight_no_enrollment_no_clean_sync(self):
        # no enrollment, clean sync not requested → no clean sync
        data, serial_number, hardware_uuid = self._get_preflight_data(enrolled=True)
        url = reverse("santa_public:preflight", args=(self.enrollment_secret.secret, hardware_uuid))
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertFalse(json_response.get("clean_sync", False))

    def test_preflight_no_enrollment_clean_sync_requested(self):
        # no enrollment, clean sync requested → clean sync
        data, serial_number, hardware_uuid = self._get_preflight_data(enrolled=True)
        data["request_clean_sync"] = True
        url = reverse("santa_public:preflight", args=(self.enrollment_secret.secret, hardware_uuid))
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertTrue(json_response["clean_sync"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_preflight_sync_not_ok_conf_without_severity_no_incident_update(self, post_event):
        # add one synced rule
        target = Target.objects.create(type=Target.BINARY, identifier=get_random_string(64, "0123456789abcdef"))
        rule = Rule.objects.create(configuration=self.configuration, target=target, policy=Rule.BLOCKLIST)
        MachineRule.objects.create(
            enrolled_machine=self.enrolled_machine,
            target=target,
            policy=rule.policy,
            version=rule.version,
            cursor=None
        )
        data, serial_number, hardware_uuid = self._get_preflight_data(enrolled=True)
        data["binary_rule_count"] = 0  # sync not OK
        url = reverse("santa_public:preflight", args=(self.enrollment_secret.secret, hardware_uuid))
        response = self.post_as_json(url, data)
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
        target = Target.objects.create(type=Target.BINARY, identifier=get_random_string(64, "0123456789abcdef"))
        rule = Rule.objects.create(configuration=self.configuration, target=target, policy=Rule.BLOCKLIST)
        MachineRule.objects.create(
            enrolled_machine=self.enrolled_machine,
            target=target,
            policy=rule.policy,
            version=rule.version,
            cursor=None
        )
        data, serial_number, hardware_uuid = self._get_preflight_data(enrolled=True)
        data["binary_rule_count"] = 1
        url = reverse("santa_public:preflight", args=(self.enrollment_secret.secret, hardware_uuid))
        response = self.post_as_json(url, data)
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
        target = Target.objects.create(type=Target.BINARY, identifier=get_random_string(64, "0123456789abcdef"))
        rule = Rule.objects.create(configuration=self.configuration, target=target, policy=Rule.BLOCKLIST)
        MachineRule.objects.create(
            enrolled_machine=self.enrolled_machine,
            target=target,
            policy=rule.policy,
            version=rule.version,
            cursor=None
        )
        data, serial_number, hardware_uuid = self._get_preflight_data(enrolled=True)
        data["binary_rule_count"] = 1
        url = reverse("santa_public:preflight", args=(self.enrollment_secret.secret, hardware_uuid))
        response = self.post_as_json(url, data)
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
        target = Target.objects.create(type=Target.BINARY, identifier=get_random_string(64, "0123456789abcdef"))
        rule = Rule.objects.create(configuration=self.configuration, target=target, policy=Rule.BLOCKLIST)
        MachineRule.objects.create(
            enrolled_machine=self.enrolled_machine,
            target=target,
            policy=rule.policy,
            version=rule.version,
            cursor=None
        )
        data, serial_number, hardware_uuid = self._get_preflight_data(enrolled=True)
        url = reverse("santa_public:preflight", args=(self.enrollment_secret.secret, hardware_uuid))
        response = self.post_as_json(url, data)
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
        target = Target.objects.create(type=Target.BINARY, identifier=get_random_string(64, "0123456789abcdef"))
        rule = Rule.objects.create(configuration=self.configuration, target=target, policy=Rule.BLOCKLIST)
        MachineRule.objects.create(
            enrolled_machine=self.enrolled_machine,
            target=target,
            policy=rule.policy,
            version=rule.version,
            cursor=None
        )
        data, serial_number, hardware_uuid = self._get_preflight_data(enrolled=True)
        url = reverse("santa_public:preflight", args=(self.enrollment_secret.secret, hardware_uuid))
        response = self.post_as_json(url, data)
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
        url = reverse("santa_public:preflight", args=(self.enrollment_secret2.secret, hardware_uuid))
        response = self.post_as_json(url, data)
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
        url = reverse("santa_public:ruledownload", args=(self.enrollment_secret.secret, uuid.uuid4()))
        # no rules
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 403)

    def test_rule_download(self):
        url = reverse("santa_public:ruledownload", args=(self.enrollment_secret.secret, self.enrolled_machine.hardware_uuid))
        # no rules
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"rules": []})
        # add a rule
        target = Target.objects.create(type=Target.BINARY, identifier=get_random_string(64, "0123456789abcdef"))
        rule = Rule.objects.create(configuration=self.configuration, target=target, policy=Rule.BLOCKLIST)
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.BINARY,
              "identifier": target.identifier,
              "policy": "BLOCKLIST"}]
        )
        # rule not confirmed, same rule
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.BINARY,
              "identifier": target.identifier,
              "policy": "BLOCKLIST"}]
        )
        # rule acknowleged, no rules
        response = self.post_as_json(url, {"cursor": json_response["cursor"]})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"rules": []})
        # updated rule, rule
        rule.custom_msg = "BAD LUCK"
        rule.version = F("version") + 1
        rule.save()
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.BINARY,
              "identifier": target.identifier,
              "policy": "BLOCKLIST",
              "custom_msg": rule.custom_msg}]
        )
        # updated rule not acknowleged, same updated rule
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.BINARY,
              "identifier": target.identifier,
              "policy": "BLOCKLIST",
              "custom_msg": rule.custom_msg}]
        )
        # updated rule acknowleged, no rules
        response = self.post_as_json(url, {"cursor": json_response["cursor"]})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"rules": []})
        # rule out of scope, remove rule
        rule.serial_numbers = [get_random_string(12)]
        rule.save()
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.BINARY,
              "identifier": target.identifier,
              "policy": "REMOVE"}]
        )
        # remove rule not confirm, same remove rule
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.BINARY,
              "identifier": target.identifier,
              "policy": "REMOVE"}]
        )
        # rule out of scope with excluded serial number, same remove rule
        rule.serial_numbers = []
        rule.excluded_serial_numbers = [self.enrolled_machine.serial_number]
        rule.save()
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.BINARY,
              "identifier": target.identifier,
              "policy": "REMOVE"}]
        )
        # remove rule acknowleged, no rules
        response = self.post_as_json(url, {"cursor": json_response["cursor"]})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"rules": []})
        # rule again in scope by removing excluded serial number, we get the rule
        rule.excluded_serial_numbers = [get_random_string(15)]
        rule.save()
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.BINARY,
              "identifier": target.identifier,
              "policy": "BLOCKLIST",
              "custom_msg": rule.custom_msg}]
        )
        # rule again in scope acknowleged, no rules
        response = self.post_as_json(url, {"cursor": json_response["cursor"]})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"rules": []})

    # event upload

    def test_eventupload_not_enrolled(self):
        url = reverse("santa_public:eventupload", args=(self.enrollment_secret.secret, uuid.uuid4()))
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_eventupload_without_bundle(self, post_event):
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
            'file_name': 'compressord',
            'file_path': ('/Library/Frameworks/Compressor.framework/'
                          'Versions/A/Resources/CompressorTranscoderX.bundle/Contents/MacOS'),
            'file_sha256': get_random_string(64, "0123456789abcdef"),
            'logged_in_users': [],
            'parent_name': 'launchd',
            'pid': 95,
            'ppid': 1,
            'quarantine_timestamp': 0,
            'signing_chain': [{'cn': 'Software Signing',
                               'ou': get_random_string(10, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
                               'org': 'Apple Inc.',
                               'sha256': get_random_string(64, "0123456789abcdef"),
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
        url = reverse("santa_public:eventupload", args=(self.enrollment_secret.secret, self.enrolled_machine.hardware_uuid))
        response = self.post_as_json(url, {"events": [event_d]})
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
            'file_sha256': get_random_string(64, "0123456789abcdef"),
            'logged_in_users': [],
            'parent_name': 'launchd',
            'pid': 95,
            'ppid': 1,
            'quarantine_timestamp': 0,
            'signing_chain': [{'cn': 'Software Signing',
                               'ou': get_random_string(10, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
                               'org': 'Apple Inc.',
                               'sha256': get_random_string(64, "0123456789abcdef"),
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
        url = reverse("santa_public:eventupload", args=(self.enrollment_secret.secret, self.enrolled_machine.hardware_uuid))
        response = self.post_as_json(url, {"events": [event_d]})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"event_upload_bundle_binaries": [event_d["file_bundle_hash"]]})
        b = Bundle.objects.get(target__type=Target.BUNDLE, target__identifier=event_d["file_bundle_hash"])
        self.assertIsNone(b.uploaded_at)
        self.assertEqual(b.bundle_id, event_d["file_bundle_id"])
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, SantaEventEvent)
        self.assertEqual(event.payload["signing_chain"], event_d["signing_chain"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_eventupload_bundle_binary(self, post_event):
        event_d = {
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
            'file_sha256': get_random_string(64, "0123456789abcdef"),
            'logged_in_users': [],
            'parent_name': 'launchd',
            'pid': 95,
            'ppid': 1,
            'quarantine_timestamp': 0,
            'signing_chain': [{'cn': 'Software Signing',
                               'ou': get_random_string(10, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
                               'org': 'Apple Inc.',
                               'sha256': get_random_string(64, "0123456789abcdef"),
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
        t, _ = Target.objects.get_or_create(type=Target.BUNDLE, identifier=event_d["file_bundle_hash"])
        b, _ = Bundle.objects.update_or_create(
            target=t,
            defaults={"binary_count": event_d["file_bundle_binary_count"]}
        )
        url = reverse("santa_public:eventupload", args=(self.enrollment_secret.secret, self.enrolled_machine.hardware_uuid))
        response = self.post_as_json(url, {"events": [event_d]})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {})
        b.refresh_from_db()
        self.assertIsNotNone(b.uploaded_at)
        self.assertEqual(
            list(b.binary_targets.all()),
            [Target.objects.get(type=Target.BINARY, identifier=event_d["file_sha256"])]
        )
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 0)

    # postflight

    def test_rule_postflight_not_enrolled(self):
        url = reverse("santa_public:postflight", args=(self.enrollment_secret.secret, uuid.uuid4()))
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 403)

    def test_postflight(self):
        url = reverse("santa_public:postflight", args=(self.enrollment_secret.secret, self.enrolled_machine.hardware_uuid))
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {})
