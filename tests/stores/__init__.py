from datetime import datetime, timedelta
from zentral.core.events.base import EventMetadata, EventRequest, EventRequestUser, BaseEvent, register_event_type


class TestEvent1(BaseEvent):
    event_type = "event_type_1"
    namespace = "ns_event_type_1"


register_event_type(TestEvent1)


class TestEvent2(BaseEvent):
    event_type = "event_type_2"


register_event_type(TestEvent2)


def make_event(idx=0, first_type=True, with_request=True):
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
    return event_cls(EventMetadata(machine_serial_number='012356789',
                                   request=request),
                     {'idx': idx})


def get_from_dt():
    return datetime.utcnow() - timedelta(days=1)


class BaseTestEventStore(object):
    event_store = None

    def test_table_creation(self):
        self.assertEqual(
            self.event_store.get_aggregated_machine_event_counts(
                "not_so_random_machine_serial_number",
                from_dt=get_from_dt()
            ), {}
        )

    def test_store_event_with_request(self):
        event = make_event()
        self.event_store.store(event)
        l, _ = self.event_store.fetch_machine_events(
            event.metadata.machine_serial_number,
            from_dt=get_from_dt()
        )
        e = l[0]
        self.assertEqual(e.serialize(), event.serialize())

    def test_store_event_without_request(self):
        event = make_event(with_request=False)
        self.event_store.store(event)
        l, _ = self.event_store.fetch_machine_events(
            event.metadata.machine_serial_number,
            from_dt=get_from_dt()
        )
        e = l[0]
        self.assertEqual(e.serialize(), event.serialize())

    def test_fetch_machine_events_cursor(self):
        for i in range(100):
            event = make_event(idx=i)
            self.event_store.store(event)
        l, cursor = self.event_store.fetch_machine_events(
            event.metadata.machine_serial_number,
            from_dt=get_from_dt(), limit=2
        )
        self.assertEqual(len(l), 2)
        self.assertEqual(l[0].payload['idx'], 99)
        self.assertEqual(l[1].payload['idx'], 98)
        l2, _ = self.event_store.fetch_machine_events(
            event.metadata.machine_serial_number,
            from_dt=get_from_dt(), limit=2, cursor=cursor
        )
        self.assertEqual(len(l2), 2)
        self.assertEqual(l2[0].payload['idx'], 97)
        self.assertEqual(l2[1].payload['idx'], 96)

    def test_aggregated_machine_event_counts(self):
        for i in range(100):
            event = make_event(idx=i, first_type=i < 50)
            self.event_store.store(event)
        types_d = self.event_store.get_aggregated_machine_event_counts(
            event.metadata.machine_serial_number,
            from_dt=get_from_dt()
        )
        self.assertEqual(types_d['event_type_1'], 50)
        self.assertEqual(types_d['event_type_2'], 50)
