import time
import unittest
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from zentral.core.events import EventMetadata, EventRequest, BaseEvent, register_event_type
from zentral.core.stores.backends.elasticsearch import EventStore as ElasticsearchEventStore
from zentral.core.stores.backends.postgres import EventStore as PostgresEventStore


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
                               "10.0.0.1")
    else:
        request = None
    return event_cls(EventMetadata(event_cls.event_type,
                                   machine_serial_number='012356789',
                                   request=request),
                     {'idx': idx})


class BaseTestEventStore(object):
    event_store = None

    def test_table_creation(self):
        self.assertEqual(self.event_store.count("not_so_random_machine_serial_number"), 0)

    def test_store_event_with_request(self):
        event = make_event()
        self.event_store.store(event)
        l = list(self.event_store.fetch(event.metadata.machine_serial_number))
        self.assertEqual(len(l), 1)
        e = l[0]
        self.assertEqual(e.serialize(), event.serialize())

    def test_store_event_without_request(self):
        event = make_event(with_request=False)
        self.event_store.store(event)
        l = list(self.event_store.fetch(event.metadata.machine_serial_number))
        self.assertEqual(len(l), 1)
        e = l[0]
        self.assertEqual(e.serialize(), event.serialize())

    def test_pagination(self):
        for i in range(100):
            event = make_event(idx=i)
            self.event_store.store(event)
        l = list(self.event_store.fetch(event.metadata.machine_serial_number, offset=10, limit=2))
        self.assertEqual(len(l), 2)
        self.assertEqual(l[0].payload['idx'], 89)
        self.assertEqual(l[1].payload['idx'], 88)

    def test_event_types_usage(self):
        for i in range(100):
            event = make_event(idx=i, first_type=i < 50)
            self.event_store.store(event)
        types_d = self.event_store.event_types_with_usage(event.metadata.machine_serial_number)
        self.assertEqual(types_d['event_type_1'], 50)
        self.assertEqual(types_d['event_type_2'], 50)


class TestElasticsearchEventStore(unittest.TestCase, BaseTestEventStore):
    TEST_INDEX = 'zentral-tests-events'

    def setUp(self):
        self.event_store = ElasticsearchEventStore({'servers': ["http://localhost:9200"],
                                                    'index': self.TEST_INDEX,
                                                    'store_name': 'elasticsearch_test'},
                                                   test=True)
        self.event_store._es.indices.create(index=self.TEST_INDEX)
        time.sleep(.2)  # better success rate. TODO: necessary ?

    def tearDown(self):
        self.event_store._es.indices.delete(index=self.TEST_INDEX, ignore=[404])
        self.event_store.close()


class TestPostgresEventStore(unittest.TestCase, BaseTestEventStore):

    def setUp(self):
        self._conn = psycopg2.connect("dbname=postgres user=zentral_testing")
        self._conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        with self._conn:
            with self._conn.cursor() as cur:
                cur.execute('CREATE DATABASE zentral_testing')
        self.event_store = PostgresEventStore({'database': 'zentral_testing',
                                               'user': 'zentral',
                                               'store_name': 'postgres_test'})

    def tearDown(self):
        self.event_store.close()
        with self._conn:
            with self._conn.cursor() as cur:
                cur.execute('DROP DATABASE zentral_testing')


if __name__ == '__main__':
    unittest.main()
