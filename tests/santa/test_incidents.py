from unittest.mock import Mock
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.santa.incidents import SyncIncident
from zentral.contrib.santa.models import Configuration
from zentral.core.incidents.utils import open_incident, Severity


class SantaIncidentsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.configuration = Configuration.objects.create(name=get_random_string(256))

    def test_santa_sync_build_incident_update(self):
        incident_update = SyncIncident.build_incident_update(self.configuration, Severity.MAJOR)
        self.assertEqual(incident_update.incident_type, "santa_sync")
        self.assertEqual(incident_update.key, {"santa_cfg_pk": self.configuration.pk})
        self.assertEqual(incident_update.severity, Severity.MAJOR)

    def test_santa_sync_get_objects(self):
        incident_update = SyncIncident.build_incident_update(self.configuration, Severity.CRITICAL)
        incident, _ = open_incident(incident_update)
        configurations = incident.loaded_incident.get_objects()
        self.assertEqual(len(configurations), 1)
        self.assertEqual(configurations[0], self.configuration)

    def test_santa_sync_get_objects_for_display(self):
        incident_update = SyncIncident.build_incident_update(self.configuration, Severity.CRITICAL)
        incident, _ = open_incident(incident_update)
        objects_for_display = list(incident.loaded_incident.get_objects_for_display())
        self.assertEqual(
            objects_for_display,
            [("Santa configuration", ("santa.view_configuration",), [self.configuration])]
        )

    def test_santa_sync_get_objects_error(self):
        cfg = Mock()
        cfg.pk = 123098123
        incident_update = SyncIncident.build_incident_update(cfg, Severity.MAJOR)
        incident, _ = open_incident(incident_update)
        configurations = incident.loaded_incident.get_objects()
        self.assertEqual(len(configurations), 0)

    def test_santa_sync_get_name(self):
        incident_update = SyncIncident.build_incident_update(self.configuration, Severity.NONE)
        incident, _ = open_incident(incident_update)
        self.assertEqual(
            incident.loaded_incident.get_name(),
            f"Santa {self.configuration.name} configuration client out of sync"
        )

    def test_santa_sync_get_name_error(self):
        cfg = Mock()
        cfg.pk = 123098123
        incident_update = SyncIncident.build_incident_update(cfg, Severity.MAJOR)
        incident, _ = open_incident(incident_update)
        self.assertEqual(incident.loaded_incident.get_name(), "Unknown Santa configuration client out of sync")
