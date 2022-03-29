from datetime import datetime
from django.urls import reverse
from django.test import TestCase
from django.utils.crypto import get_random_string
from prometheus_client.parser import text_string_to_metric_families
from zentral.conf import settings
from zentral.core.incidents.models import Incident, MachineIncident, Severity, Status


class IncidentsMetricsViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.incident = Incident.objects.create(
            incident_type="this_is_not_an_incident",
            key={"not_an_incident": 42},
            status=Status.OPEN.value,
            status_time=datetime.utcnow(),
            severity=Severity.MAJOR.value
        )
        MachineIncident.objects.create(
            incident=cls.incident,
            serial_number=get_random_string(12),
            status=Status.OPEN.value,
            status_time=datetime.utcnow()
        )
        MachineIncident.objects.create(
            incident=cls.incident,
            serial_number=get_random_string(12),
            status=Status.OPEN.value,
            status_time=datetime.utcnow()
        )

    # utility methods

    def _make_authenticated_request(self):
        return self.client.get(reverse("incidents_metrics:all"),
                               HTTP_AUTHORIZATION=f'Bearer {settings["api"]["metrics_bearer_token"]}')

    # metrics

    def test_metrics_permission_denied(self):
        response = self.client.get(reverse("incidents_metrics:all"))
        self.assertEqual(response.status_code, 403)

    def test_metrics_permission_ok(self):
        response = self._make_authenticated_request()
        self.assertEqual(response.status_code, 200)

    def test_zentral_incidents(self):
        response = self._make_authenticated_request()
        for family in text_string_to_metric_families(response.content.decode("utf-8")):
            if family.name != "zentral_incidents":
                continue
            else:
                self.assertEqual(len(family.samples), 1)
                sample = family.samples[0]
                self.assertEqual(sample.value, 1)
                self.assertEqual(sample.labels["type"], self.incident.incident_type)
                self.assertEqual(sample.labels["severity"], "major")
                self.assertEqual(sample.labels["status"], "open")
                break
        else:
            raise AssertionError("could not find expected metric family")
        self.assertEqual(response.status_code, 200)

    def test_zentral_machine_incidents(self):
        response = self._make_authenticated_request()
        for family in text_string_to_metric_families(response.content.decode("utf-8")):
            if family.name != "zentral_machine_incidents":
                continue
            else:
                self.assertEqual(len(family.samples), 1)
                sample = family.samples[0]
                self.assertEqual(sample.value, 2)
                self.assertEqual(sample.labels["type"], self.incident.incident_type)
                self.assertEqual(sample.labels["severity"], "major")
                self.assertEqual(sample.labels["status"], "open")
                break
        else:
            raise AssertionError("could not find expected metric family")
        self.assertEqual(response.status_code, 200)
