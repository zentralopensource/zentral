from datetime import datetime, timedelta
from unittest.mock import Mock
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.events import InventoryHeartbeat
from zentral.contrib.osquery.events import OsqueryRequestEvent
from zentral.core.events.base import EventMetadata, EventRequest, EventRequestUser, BaseEvent, register_event_type
from zentral.utils.text import encode_args


class TestEvent1(BaseEvent):
    event_type = "event_type_1"
    namespace = "ns_event_type_1"


register_event_type(TestEvent1)


class TestEvent2(BaseEvent):
    event_type = "event_type_2"


register_event_type(TestEvent2)


def make_event(idx=0, first_type=True, with_request=True, objects=None, probe_pks=None, msn=None):
    if first_type:
        event_cls = TestEvent1
    else:
        event_cls = TestEvent2
    if with_request:
        request = EventRequest("python_unittest_useragent",
                               "10.0.0.1",
                               EventRequestUser(username="yolo"))
    else:
        request = None
    serial_number = '012356789' if msn is None else msn
    metadata = EventMetadata(machine_serial_number=serial_number, request=request)
    if objects:
        metadata.add_objects(objects)
    if probe_pks:
        metadata.probes.extend({"pk": pk, "name": f"probe_{pk}"} for pk in probe_pks)
    return event_cls(metadata, {'idx': idx})


def get_from_dt():
    return datetime.utcnow() - timedelta(days=1)


def get_to_dt():
    return datetime.utcnow() + timedelta(days=1)


class BaseTestStore(object):
    store = None

    # store event

    def test_store_event_with_request(self):
        event = make_event()
        self.store.store(event)
        l, _ = self.store.fetch_machine_events(
            event.metadata.machine_serial_number,
            from_dt=get_from_dt()
        )
        e = l[0]
        self.assertEqual(e.serialize(), event.serialize())

    def test_store_event_without_request(self):
        event = make_event(with_request=False)
        self.store.store(event)
        l, _ = self.store.fetch_machine_events(
            event.metadata.machine_serial_number,
            from_dt=get_from_dt()
        )
        e = l[0]
        self.assertEqual(e.serialize(), event.serialize())

    # bulk store events

    def test_bulk_store_events_with_request(self):
        if self.store.batch_size > 1:
            event_keys = set()
            events = []
            for _ in range(self.store.batch_size):
                event = make_event()
                event_keys.add((str(event.metadata.uuid), event.metadata.index))
                events.append(event)
            results = self.store.bulk_store(events)
            for key in results:
                event_keys.remove(key)
            self.assertEqual(len(event_keys), 0)

    # fetch machine events

    def test_fetch_machine_events_cursor(self):
        for i in range(5):
            event = make_event(idx=i)
            self.store.store(event)
        l, cursor = self.store.fetch_machine_events(
            event.metadata.machine_serial_number,
            from_dt=get_from_dt(), limit=2
        )
        self.assertEqual(len(l), 2)
        self.assertEqual(l[0].payload['idx'], 4)
        self.assertEqual(l[1].payload['idx'], 3)
        l2, _ = self.store.fetch_machine_events(
            event.metadata.machine_serial_number,
            from_dt=get_from_dt(), limit=2, cursor=cursor
        )
        self.assertEqual(len(l2), 2)
        self.assertEqual(l2[0].payload['idx'], 2)
        self.assertEqual(l2[1].payload['idx'], 1)

    def test_fetch_machine_events_type_to_dt(self):
        msn = get_random_string(12)
        to_dt = None
        for i in range(3):
            event = make_event(idx=i, first_type=i >= 1, msn=msn)
            if i == 2:
                to_dt = event.metadata.created_at
            self.store.store(event)
        l, _ = self.store.fetch_machine_events(
            msn,
            event_type="event_type_1",
            from_dt=get_from_dt(), to_dt=to_dt,
        )
        self.assertEqual(len(l), 1)
        self.assertEqual(l[0].payload['idx'], 1)

    # get aggregated machine event counts

    def test_aggregated_machine_event_counts(self):
        for i in range(5):
            event = make_event(idx=i, first_type=i < 3)
            self.store.store(event)
        types_d = self.store.get_aggregated_machine_event_counts(
            event.metadata.machine_serial_number,
            from_dt=get_from_dt(), to_dt=get_to_dt(),
        )
        self.assertEqual(types_d['event_type_1'], 3)
        self.assertEqual(types_d['event_type_2'], 2)

    # get last machine heartbeats

    def test_last_machine_heartbeats(self):
        msn = get_random_string(12)
        ihe = InventoryHeartbeat(
            EventMetadata(machine_serial_number=msn, created_at=datetime(2025, 12, 8, 1)),
            {"source": {'module': 'zentral.contrib.mdm', 'name': 'MDM'}},
        )
        self.store.store(ihe)
        ore = list(OsqueryRequestEvent.build_from_machine_request_payloads(
            msn, "osquery/5.20.0", "203.0.113.17", [{"request_type": "distributed_read"}],
            get_created_at=lambda p: datetime(2025, 12, 8, 2)
        ))[0]
        self.store.store(ore)
        self.assertEqual(
            self.store.get_last_machine_heartbeats(msn, from_dt=datetime(2025, 12, 8)),
            [(InventoryHeartbeat,
              'MDM',
              [(None, datetime(2025, 12, 8, 1, 0))]),
             (OsqueryRequestEvent,
              None,
              [('osquery/5.20.0', datetime(2025, 12, 8, 2, 0))])]
        )

    # fetch object events

    def test_fetch_object_events_cursor(self):
        for i in range(5):
            event = make_event(idx=i, objects={"yolo": [("fomo",)]})
            self.store.store(event)
            event = make_event(idx=i, objects={"fomo": [("yolo",)]})
            self.store.store(event)
        l, cursor = self.store.fetch_object_events(
            "yolo", encode_args(("fomo",)),
            from_dt=get_from_dt(), limit=2
        )
        self.assertEqual(len(l), 2)
        self.assertEqual(l[0].payload['idx'], 4)
        self.assertEqual(l[0].metadata.objects, {'yolo': [['fomo']]})
        self.assertEqual(l[1].payload['idx'], 3)
        self.assertEqual(l[1].metadata.objects, {'yolo': [['fomo']]})
        l2, cursor = self.store.fetch_object_events(
            "yolo", encode_args(("fomo",)),
            from_dt=get_from_dt(), limit=2, cursor=cursor
        )
        self.assertEqual(len(l2), 2)
        self.assertEqual(l2[0].payload['idx'], 2)
        self.assertEqual(l2[0].metadata.objects, {'yolo': [['fomo']]})
        self.assertEqual(l2[1].payload['idx'], 1)
        self.assertEqual(l2[1].metadata.objects, {'yolo': [['fomo']]})

    def test_fetch_object_events_type_to_dt(self):
        to_dt = None
        for i in range(3):
            event = make_event(idx=i, first_type=i >= 1, objects={"yolo2": [("fomo2",)]})
            if i == 2:
                to_dt = event.metadata.created_at
            self.store.store(event)
        l, _ = self.store.fetch_object_events(
            "yolo2", encode_args(("fomo2",)),
            event_type="event_type_1",
            from_dt=get_from_dt(), to_dt=to_dt,
        )
        self.assertEqual(len(l), 1)
        self.assertEqual(l[0].payload['idx'], 1)
        self.assertEqual(l[0].metadata.objects, {'yolo2': [['fomo2']]})

    # get aggregated object event counts

    def test_get_aggregated_object_event_counts(self):
        for i in range(5):
            event = make_event(idx=i, first_type=i < 3, objects={"yolo3": [("fomo3",)]})
            self.store.store(event)
        types_d = self.store.get_aggregated_object_event_counts(
            "yolo3", encode_args(("fomo3",)),
            from_dt=get_from_dt(), to_dt=get_to_dt(),
        )
        self.assertEqual(types_d['event_type_1'], 3)
        self.assertEqual(types_d['event_type_2'], 2)

    # fetch probe events

    def test_fetch_probe_events_cursor(self):
        for i in range(5):
            event = make_event(idx=i, probe_pks=[12387, 129])
            self.store.store(event)
            event = make_event(idx=i, probe_pks=[4987, 218973])
            self.store.store(event)
        probe = Mock(pk=4987)
        l, cursor = self.store.fetch_probe_events(
            probe,
            from_dt=get_from_dt(), limit=2
        )
        self.assertEqual(len(l), 2)
        self.assertEqual(l[0].payload['idx'], 4)
        self.assertEqual(
            l[0].metadata.probes,
            [{'name': 'probe_4987', 'pk': 4987}, {'name': 'probe_218973', 'pk': 218973}]
        )
        self.assertEqual(l[1].payload['idx'], 3)
        self.assertEqual(
            l[1].metadata.probes,
            [{'name': 'probe_4987', 'pk': 4987}, {'name': 'probe_218973', 'pk': 218973}]
        )
        l2, cursor = self.store.fetch_probe_events(
            probe,
            from_dt=get_from_dt(), limit=2, cursor=cursor
        )
        self.assertEqual(len(l2), 2)
        self.assertEqual(l2[0].payload['idx'], 2)
        self.assertEqual(
            l2[0].metadata.probes,
            [{'name': 'probe_4987', 'pk': 4987}, {'name': 'probe_218973', 'pk': 218973}]
        )
        self.assertEqual(l2[1].payload['idx'], 1)
        self.assertEqual(
            l2[1].metadata.probes,
            [{'name': 'probe_4987', 'pk': 4987}, {'name': 'probe_218973', 'pk': 218973}]
        )

    def test_fetch_probe_events_type_to_dt(self):
        to_dt = None
        for i in range(3):
            event = make_event(idx=i, first_type=i >= 1, probe_pks=[48632987])
            if i == 2:
                to_dt = event.metadata.created_at
            self.store.store(event)
        probe = Mock(pk=48632987)
        l, _ = self.store.fetch_probe_events(
            probe,
            event_type="event_type_1",
            from_dt=get_from_dt(), to_dt=to_dt,
        )
        self.assertEqual(len(l), 1)
        self.assertEqual(l[0].payload['idx'], 1)
        self.assertEqual(l[0].metadata.probes, [{'name': 'probe_48632987', 'pk': 48632987}])

    # get aggregated probe event counts

    def test_get_aggregated_probe_event_counts(self):
        for i in range(5):
            event = make_event(idx=i, first_type=i < 3, probe_pks=[1823, 29093])
            self.store.store(event)
        probe = Mock(pk=29093)
        types_d = self.store.get_aggregated_probe_event_counts(
            probe,
            from_dt=get_from_dt(), to_dt=get_to_dt(),
        )
        self.assertEqual(types_d['event_type_1'], 3)
        self.assertEqual(types_d['event_type_2'], 2)

    # get app hist data

    def test_get_app_hist_data(self):
        for ore in OsqueryRequestEvent.build_from_machine_request_payloads(
            get_random_string(12), "osquery/5.20.0", "203.0.113.17",
            [{"request_type": "distributed_read"},
             {"request_type": "distributed_read"}],
            get_created_at=lambda p: datetime.utcnow()
        ):
            self.store.store(ore)
        aggs = self.store.get_app_hist_data("day", 15, "osquery")
        self.assertEqual(len(aggs), 15)
        _, events, machines = aggs[-1]
        self.assertEqual(events, 2)
        self.assertEqual(machines, 1)
