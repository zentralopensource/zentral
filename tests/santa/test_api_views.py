import json
import uuid
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.santa.models import Configuration, EnrolledMachine, Enrollment


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
                                                              serial_number=cls.machine_serial_number)
        cls.business_unit = cls.meta_business_unit.create_enrollment_business_unit()

    def post_as_json(self, url, data):
        return self.client.post(url,
                                json.dumps(data),
                                content_type="application/json")

    def test_preflight(self):
        data = {"serial_num": self.machine_serial_number,
                "os_version": "10.13.17",
                "os_build": "16G1113",
                "hostname": "hostname",
                "santa_version": "1.14"}
        url = reverse("santa:preflight", args=(self.enrollment_secret.secret, self.enrolled_machine.hardware_uuid))
        # MONITOR mode
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["client_mode"], Configuration.PREFLIGHT_MONITOR_MODE)
        self.assertTrue(json_response["blocked_path_regex"].startswith("NON_MATCHING_PLACEHOLDER_"))
        self.assertTrue(json_response["allowed_path_regex"].startswith("NON_MATCHING_PLACEHOLDER_"))
        # deprecated attributes
        data["santa_version"] = "1.13"
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["client_mode"], Configuration.PREFLIGHT_MONITOR_MODE)
        self.assertTrue(json_response["blacklist_regex"].startswith("NON_MATCHING_PLACEHOLDER_"))
        self.assertTrue(json_response["whitelist_regex"].startswith("NON_MATCHING_PLACEHOLDER_"))
        # LOCKDOWN mode
        Configuration.objects.update(client_mode=Configuration.LOCKDOWN_MODE)
        response = self.post_as_json(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["client_mode"], Configuration.PREFLIGHT_LOCKDOWN_MODE)
        Configuration.objects.update(client_mode=Configuration.MONITOR_MODE)
