from zentral.core.events.base import EventMetadata, EventRequest, EventRequestUser, BaseEvent, register_event_type


class TestEvent1(BaseEvent):
    event_type = "event_type_1"


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
    return event_cls(EventMetadata(event_cls.event_type,
                                   machine_serial_number='012356789',
                                   request=request),
                     {'idx': idx})


class BaseTestEventStore(object):
    event_store = None

    def test_table_creation(self):
        self.assertEqual(self.event_store.machine_events_count("not_so_random_machine_serial_number"), 0)

    def test_store_event_with_request(self):
        event = make_event()
        self.event_store.store(event)
        l = list(self.event_store.machine_events_fetch(event.metadata.machine_serial_number))
        e = l[0]
        self.assertEqual(e.serialize(), event.serialize())

    def test_store_event_without_request(self):
        event = make_event(with_request=False)
        self.event_store.store(event)
        l = list(self.event_store.machine_events_fetch(event.metadata.machine_serial_number))
        e = l[0]
        self.assertEqual(e.serialize(), event.serialize())

    def test_pagination(self):
        for i in range(100):
            event = make_event(idx=i)
            self.event_store.store(event)
        l = list(self.event_store.machine_events_fetch(event.metadata.machine_serial_number, offset=10, limit=2))
        self.assertEqual(len(l), 2)
        self.assertEqual(l[0].payload['idx'], 89)
        self.assertEqual(l[1].payload['idx'], 88)

    def test_event_types_usage(self):
        for i in range(100):
            event = make_event(idx=i, first_type=i < 50)
            self.event_store.store(event)
        types_d = self.event_store.machine_events_types_with_usage(event.metadata.machine_serial_number)
        self.assertEqual(types_d['event_type_1'], 50)
        self.assertEqual(types_d['event_type_2'], 50)
