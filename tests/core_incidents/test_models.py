from django.test import SimpleTestCase
from zentral.core.incidents.models import Status


class IncidentStatusTestCase(SimpleTestCase):
    def test_open_values_deterministic_sorted_tuple(self):
        self.assertEqual(Status.open_values(), ("IN_PROGRESS", "OPEN", "REOPENED"))

    def test_closed_values_deterministic_sorted_tuple(self):
        self.assertEqual(Status.closed_values(), ("CLOSED", "RESOLVED"))
