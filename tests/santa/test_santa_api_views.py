import json
import uuid
from django.db.models import F
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret, File, MachineSnapshot, MetaBusinessUnit
from zentral.contrib.santa.models import Bundle, Configuration, EnrolledMachine, Enrollment, Rule, Target


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class SantaAPIViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.configuration = Configuration.objects.create(name=get_random_string(256))
        cls.meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=cls.meta_business_unit)
        cls.enrollment = Enrollment.objects.create(configuration=cls.configuration,
                                                   secret=cls.enrollment_secret)
        cls.machine_serial_number = get_random_string(64)
        cls.enrolled_machine = EnrolledMachine.objects.create(enrollment=cls.enrollment,
                                                              hardware_uuid=uuid.uuid4(),
                                                              serial_number=cls.machine_serial_number,
                                                              client_mode=Configuration.MONITOR_MODE,
                                                              santa_version="1.17")
        cls.business_unit = cls.meta_business_unit.create_enrollment_business_unit()

    def post_as_json(self, url, data):
        return self.client.post(url,
                                json.dumps(data),
                                content_type="application/json")

    def _get_preflight_data(self):
        serial_number = get_random_string(12)
        data = {
            "os_build": "20C69",
            "santa_version": "2021.1",
            "hostname": "hostname",
            "transitive_rule_count": 0,
            "os_version": "11.1",
            "certificate_rule_count": 2,
            "client_mode": "LOCKDOWN",
            "serial_num": serial_number,
            "binary_rule_count": 1,
            "primary_user": "mark.torpedo@example.com",
            "compiler_rule_count": 0
        }
        return data, serial_number, uuid.uuid4()

    def test_preflight_bad_secret(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        url = reverse("santa:preflight", args=(get_random_string(12), hardware_uuid))
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 403)

    def test_preflight_no_mtls(self):
        self.configuration.client_certificate_auth = True
        self.configuration.save()
        data, serial_number, hardware_uuid = self._get_preflight_data()
        url = reverse("santa:preflight", args=(self.enrollment_secret.secret, hardware_uuid))
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 403)

    def test_preflight(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        url = reverse("santa:preflight", args=(self.enrollment_secret.secret, hardware_uuid))

        # MONITOR mode
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["client_mode"], Configuration.PREFLIGHT_MONITOR_MODE)
        self.assertEqual(json_response["full_sync_interval"], Configuration.DEFAULT_FULL_SYNC_INTERVAL)
        self.assertEqual(json_response["clean_sync"], True)
        self.assertTrue(json_response["blocked_path_regex"].startswith("NON_MATCHING_PLACEHOLDER_"))
        self.assertTrue(json_response["allowed_path_regex"].startswith("NON_MATCHING_PLACEHOLDER_"))

        # Enrolled machine
        enrolled_machine = EnrolledMachine.objects.get(enrollment=self.enrollment, hardware_uuid=hardware_uuid)
        self.assertEqual(enrolled_machine.serial_number, serial_number)
        self.assertEqual(enrolled_machine.primary_user, data["primary_user"])
        self.assertEqual(enrolled_machine.santa_version, data["santa_version"])
        self.assertEqual(enrolled_machine.client_mode, Configuration.LOCKDOWN_MODE)

        # deprecated attributes
        data["santa_version"] = "1.13"
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["client_mode"], Configuration.PREFLIGHT_MONITOR_MODE)
        self.assertTrue(json_response["blacklist_regex"].startswith("NON_MATCHING_PLACEHOLDER_"))
        self.assertTrue(json_response["whitelist_regex"].startswith("NON_MATCHING_PLACEHOLDER_"))
        enrolled_machine.refresh_from_db()
        self.assertEqual(enrolled_machine.santa_version, data["santa_version"])

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

    def test_preflight_model_identifier(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        data["model_identifier"] = "Macmini9,1"
        url = reverse("santa:preflight", args=(self.enrollment_secret.secret, hardware_uuid))
        self.post_as_json(url, data)

        # Machine snapshot
        ms = MachineSnapshot.objects.get(serial_number=serial_number)
        self.assertEqual(ms.source.name, "Santa")
        self.assertEqual(ms.system_info.hardware_model, data["model_identifier"])

    def test_preflight_missing_client_mode(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        del data["client_mode"]
        url = reverse("santa:preflight", args=(self.enrollment_secret.secret, hardware_uuid))

        # MONITOR mode
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["client_mode"], Configuration.PREFLIGHT_MONITOR_MODE)

        # Enrolled machine
        enrolled_machine = EnrolledMachine.objects.get(enrollment=self.enrollment, hardware_uuid=hardware_uuid)
        self.assertEqual(enrolled_machine.client_mode, Configuration.MONITOR_MODE)

    def test_preflight_clean_sync(self):
        data, serial_number, hardware_uuid = self._get_preflight_data()
        url = reverse("santa:preflight", args=(self.enrollment_secret.secret, hardware_uuid))

        # enrollment, clean sync not requested → clean sync
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertTrue(json_response["clean_sync"])

        # no enrollment, clean sync not requested → no clean sync
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertFalse(json_response.get("clean_sync", False))

        # no enrollment, clean sync requested → clean sync
        data["request_clean_sync"] = True
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertTrue(json_response["clean_sync"])

    def test_rule_download_not_enrolled(self):
        url = reverse("santa:ruledownload", args=(self.enrollment_secret.secret, uuid.uuid4()))
        # no rules
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 403)

    def test_rule_download(self):
        url = reverse("santa:ruledownload", args=(self.enrollment_secret.secret, self.enrolled_machine.hardware_uuid))
        # no rules
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"rules": []})
        # add a rule
        target = Target.objects.create(type=Target.BINARY, sha256=get_random_string(64, "0123456789abcdef"))
        rule = Rule.objects.create(configuration=self.configuration, target=target, policy=Rule.BLOCKLIST)
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.BINARY,
              "sha256": target.sha256,
              "policy": "BLOCKLIST"}]
        )
        # rule not confirmed, same rule
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.BINARY,
              "sha256": target.sha256,
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
              "sha256": target.sha256,
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
              "sha256": target.sha256,
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
              "sha256": target.sha256,
              "policy": "REMOVE"}]
        )
        # remove rule not confirm, same remove rule
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["rules"],
            [{"rule_type": Target.BINARY,
              "sha256": target.sha256,
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
              "sha256": target.sha256,
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
              "sha256": target.sha256,
              "policy": "BLOCKLIST",
              "custom_msg": rule.custom_msg}]
        )
        # rule again in scope acknowleged, no rules
        response = self.post_as_json(url, {"cursor": json_response["cursor"]})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"rules": []})

    def test_rule_eventupload_not_enrolled(self):
        url = reverse("santa:eventupload", args=(self.enrollment_secret.secret, uuid.uuid4()))
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 403)

    def test_eventupload(self):
        # event without bundle
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
        url = reverse("santa:eventupload", args=(self.enrollment_secret.secret, self.enrolled_machine.hardware_uuid))
        response = self.post_as_json(url, {"events": [event_d]})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {})
        self.assertEqual(Bundle.objects.count(), 0)
        f = File.objects.get(sha_256=event_d["file_sha256"])
        self.assertEqual(f.signed_by.sha_256, event_d["signing_chain"][0]["sha256"])

        # event with bundle
        event_d["file_bundle_hash"] = get_random_string(64, "0123456789abcdef")
        event_d["file_bundle_binary_count"] = 1
        response = self.post_as_json(url, {"events": [event_d]})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"event_upload_bundle_binaries": [event_d["file_bundle_hash"]]})
        b = Bundle.objects.get(target__type=Target.BUNDLE, target__sha256=event_d["file_bundle_hash"])
        self.assertIsNone(b.uploaded_at)
        self.assertEqual(b.bundle_id, event_d["file_bundle_id"])

        # bundle binary
        event_d["decision"] = "BUNDLE_BINARY"
        response = self.post_as_json(url, {"events": [event_d]})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {})
        b.refresh_from_db()
        self.assertIsNotNone(b.uploaded_at)
        self.assertEqual(list(b.binary_targets.all()), [Target.objects.get(type=Target.BINARY, sha256=f.sha_256)])

    def test_rule_postflight_not_enrolled(self):
        url = reverse("santa:postflight", args=(self.enrollment_secret.secret, uuid.uuid4()))
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 403)

    def test_postflight(self):
        url = reverse("santa:postflight", args=(self.enrollment_secret.secret, self.enrolled_machine.hardware_uuid))
        response = self.post_as_json(url, {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {})
