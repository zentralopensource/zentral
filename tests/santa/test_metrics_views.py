import uuid
from django.urls import reverse
from django.test import TestCase
from django.utils.crypto import get_random_string
from prometheus_client.parser import text_string_to_metric_families
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.santa.models import Configuration, EnrolledMachine, Enrollment, Rule, Target
from zentral.conf import settings


class SantaMetricsViewsTestCase(TestCase):
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
                                                              santa_version="2021.7")

    # utility methods

    def _force_configuration(self):
        return Configuration.objects.create(name=get_random_string(12))

    def _make_authenticated_request(self):
        return self.client.get(reverse("santa_metrics:all"),
                               HTTP_AUTHORIZATION=f'Bearer {settings["api"]["metrics_bearer_token"]}')

    # metrics

    def test_metrics_permission_denied(self):
        response = self.client.get(reverse("santa_metrics:all"))
        self.assertEqual(response.status_code, 403)

    def test_metrics_permission_ok(self):
        response = self._make_authenticated_request()
        self.assertEqual(response.status_code, 200)

    def test_configurations(self):
        response = self._make_authenticated_request()
        for family in text_string_to_metric_families(response.content.decode("utf-8")):
            if family.name != "zentral_santa_configurations":
                continue
            else:
                self.assertEqual(len(family.samples), 1)
                sample = family.samples[0]
                self.assertEqual(sample.value, 1)
                self.assertEqual(sample.labels["mode"], "monitor")
                break
        else:
            raise AssertionError("could not find expected metric family")
        self.assertEqual(response.status_code, 200)

    def test_enrolled_machines(self):
        response = self._make_authenticated_request()
        for family in text_string_to_metric_families(response.content.decode("utf-8")):
            if family.name != "zentral_santa_enrolled_machines":
                continue
            else:
                self.assertEqual(len(family.samples), 1)
                sample = family.samples[0]
                self.assertEqual(sample.value, 1)
                self.assertEqual(sample.labels["configuration"], self.configuration.name)
                self.assertEqual(sample.labels["mode"], "monitor")
                self.assertEqual(sample.labels["santa_version"], self.enrolled_machine.santa_version)
                break
        else:
            raise AssertionError("could not find expected metric family")
        self.assertEqual(response.status_code, 200)

    def test_rules(self):
        for target_type in (Target.BINARY, Target.BUNDLE, Target.CERTIFICATE, Target.TEAM_ID, Target.SIGNING_ID):
            if target_type == Target.TEAM_ID:
                identifier = get_random_string(10).upper()
            elif target_type == Target.SIGNING_ID:
                identifier = "platform:com.apple.curl"
            else:
                identifier = get_random_string(64, "0123456789abcdef")
            target = Target.objects.create(type=target_type, identifier=identifier)
            Rule.objects.create(configuration=self.configuration, target=target, policy=Rule.BLOCKLIST)
        response = self._make_authenticated_request()
        for family in text_string_to_metric_families(response.content.decode("utf-8")):
            if family.name != "zentral_santa_rules":
                continue
            else:
                self.assertEqual(len(family.samples), 5)
                target_type_set = set()
                for sample in family.samples:
                    self.assertEqual(sample.value, 1)
                    self.assertEqual(sample.labels["configuration"], self.configuration.name)
                    self.assertEqual(sample.labels["ruleset"], "_")
                    self.assertEqual(sample.labels["policy"], "blocklist")
                    target_type_set.add(sample.labels["target_type"])
                self.assertEqual(target_type_set, {"binary", "bundle", "certificate", "teamid", "signingid"})
                break
        else:
            raise AssertionError("could not find expected metric family")
        self.assertEqual(response.status_code, 200)
