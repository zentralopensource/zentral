from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.core.events import event_from_event_d
from zentral.core.probes.conf import all_probes
from zentral.core.probes.models import ProbeSource


serialized_event = {
    '_zentral': {
        'created_at': '2021-02-18T20:55:00',
        'id': 'ff4db218-d5b4-4c2c-b40b-1b7fdee00dfc',
        'index': 0,
        'machine': {'osquery': {'name': 'perseverance',
                                'os_version': 'VxWorks'},
                    'tags': [{'id': 3, 'name': 'Mars'},
                             {'id': 4, 'name': 'Rover'}],
                    'platform': 'VcWorks',
                    'type': 'ROVER'},
        'machine_serial_number': 'PERSEVERANCE',
        'tags': ['heartbeat'],
        'type': 'inventory_heartbeat'
    },
    'source': {'module': 'zentral.contrib.jpl', 'name': 'workinprogress'}
}


class EventDeserializationTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.probe_source = ProbeSource.objects.create(
            model="BaseProbe",
            name=get_random_string(),
            status=ProbeSource.ACTIVE,
            body={"filters": {"metadata": [{"event_types": ["inventory_heartbeat"]}]}}
        )
        cls.probe = cls.probe_source.load()
        all_probes.clear()

    def test_event_from_event_d(self):
        event = event_from_event_d(serialized_event)
        self.assertEqual(event.metadata.event_type, "inventory_heartbeat")

    def test_event_probes(self):
        event = event_from_event_d(serialized_event)
        if self.probe.test_event(event):
            event.metadata.add_probe(self.probe)
        serialized_updated_event = event.serialize()
        self.assertEqual(serialized_updated_event["_zentral"]["probes"],
                         [{"pk": self.probe.pk, "name": self.probe.name}])
        updated_event = event_from_event_d(serialized_updated_event)
        self.assertEqual(list(updated_event.metadata.iter_loaded_probes()), [self.probe])
