from datetime import datetime, timedelta
from django.urls import reverse
from django.test import TestCase
from django.utils.crypto import get_random_string
from prometheus_client.parser import text_string_to_metric_families
from zentral.core.compliance_checks.models import ComplianceCheck, MachineStatus, Status
from zentral.conf import settings


class ComplianceChecksMetricsViewsTestCase(TestCase):
    # utility methods

    def _force_compliance_check(self, failed=False, count=1, age_days=22):
        cc = ComplianceCheck.objects.create(
            name=get_random_string(),
            model=get_random_string()
        )
        for _ in range(count):
            MachineStatus.objects.create(
                serial_number=get_random_string(),
                compliance_check=cc,
                compliance_check_version=cc.version,
                status=Status.OK.value if failed is False else Status.FAILED.value,
                status_time=datetime.utcnow() - timedelta(days=age_days)
            )
        return cc

    def _make_authenticated_request(self):
        return self.client.get(reverse("compliance_checks_metrics:all"),
                               HTTP_AUTHORIZATION=f'Bearer {settings["api"]["metrics_bearer_token"]}')

    # metrics

    def test_metrics_permission_denied(self):
        response = self.client.get(reverse("compliance_checks_metrics:all"))
        self.assertEqual(response.status_code, 403)

    def test_metrics_permission_ok(self):
        response = self._make_authenticated_request()
        self.assertEqual(response.status_code, 200)

    def test_compliance_checks(self):
        models = set(self._force_compliance_check().model for _ in range(3))
        response = self._make_authenticated_request()
        self.assertEqual(response.status_code, 200)
        for family in text_string_to_metric_families(response.content.decode("utf-8")):
            if family.name != "zentral_compliance_checks":
                continue
            else:
                self.assertEqual(len(family.samples), 3)
                for sample in family.samples:
                    self.assertTrue(sample.labels["model"] in models)
                    self.assertEqual(sample.value, 1)
                break
        else:
            raise AssertionError("could not find expected metric family")

    def test_compliance_checks_statuses(self):
        model_counts = {}
        for i in range(3):
            count = i + 1
            cc = self._force_compliance_check(count=count)
            model_counts[cc.model] = count
        response = self._make_authenticated_request()
        self.assertEqual(response.status_code, 200)
        for family in text_string_to_metric_families(response.content.decode("utf-8")):
            if family.name != "zentral_compliance_checks_statuses_bucket":
                continue
            else:
                self.assertEqual(len(family.samples), 3 * 7)
                for sample in family.samples:
                    self.assertEqual(sample.labels["status"], Status.OK.name)
                    le = sample.labels["le"]
                    if le in ("1", "7", "14"):
                        self.assertEqual(sample.value, 0)
                    else:
                        self.assertEqual(sample.value, model_counts[sample.labels["model"]])
                break
        else:
            raise AssertionError("could not find expected metric family")
