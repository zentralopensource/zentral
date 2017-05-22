from django.test import TestCase
from zentral.contrib.inventory.models import MachineSnapshotCommit
from zentral.core.events.base import EventMetadata, EventRequest, BaseEvent, register_event_type


class TestEvent3(BaseEvent):
    event_type = "event_type_3"


register_event_type(TestEvent3)


def make_event(ip=None, ua=None, with_msn=True):
    msn = request = None
    if with_msn:
        msn = "0123456789"
    if ip or ua:
        request = EventRequest(user_agent=ua, ip=ip)
    else:
        request = None
    return TestEvent3(EventMetadata(TestEvent3.event_type,
                                    machine_serial_number=msn,
                                    request=request),
                      {"godzilla": "yo"})


class EventSerializationTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        source = {"module": "tests.zentral.io", "name": "Zentral Tests"}
        tree = {
            "source": source,
            "business_unit": {"name": "yo bu",
                              "reference": "bu1",
                              "source": source,
                              "links": [{"anchor_text": "bu link",
                                         "url": "http://bu-link.de"}]},
            "groups": [{"name": "yo grp",
                        "reference": "grp1",
                        "source": source,
                        "links": [{"anchor_text": "group link",
                                   "url": "http://group-link.de"}]}],
            "serial_number": "0123456789",
            "os_version": {'name': 'OS X', 'major': 10, 'minor': 11, 'patch': 1},
        }
        _, cls.ms = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)

    def test_event_without_msn(self):
        event = make_event(with_msn=False)
        d = event.serialize()
        metadata = d["_zentral"]
        self.assertNotIn("machine_serial_number", metadata)
        self.assertNotIn("machine", metadata)

    def test_event_with_msn_and_machine_metadata(self):
        event = make_event(with_msn=True)
        d = event.serialize()
        metadata = d["_zentral"]
        self.assertEqual(metadata["machine_serial_number"], self.ms.serial_number)
        machine = metadata["machine"]
        self.assertEqual(machine["meta_business_units"][0]["id"],
                         self.ms.business_unit.meta_business_unit.pk)
        source_machine = machine["zentral-tests"]
        self.assertEqual(source_machine["groups"][0]["reference"], "grp1")
        self.assertEqual(source_machine["os_version"], "OS X 10.11.1")

    def test_event_with_msn_without_machine_metadata(self):
        event = make_event(with_msn=True)
        d = event.serialize(machine_metadata=False)
        metadata = d["_zentral"]
        self.assertEqual(metadata["machine_serial_number"], self.ms.serial_number)
        self.assertNotIn("machine", metadata)
        event2 = TestEvent3.deserialize(d)
        self.assertEqual(event2.metadata.machine.serial_number, self.ms.serial_number)

    def test_event_with_request(self):
        event = make_event(ip="10.1.2.3")
        d = event.serialize()
        metadata = d["_zentral"]
        self.assertEqual(metadata["request"], {"ip": "10.1.2.3"})
        event = make_event(ua="YO! ua")
        d = event.serialize()
        metadata = d["_zentral"]
        self.assertEqual(metadata["request"], {"user_agent": "YO! ua"})

    def test_event_without_request(self):
        event = make_event()
        d = event.serialize()
        metadata = d["_zentral"]
        self.assertNotIn("request", metadata)
