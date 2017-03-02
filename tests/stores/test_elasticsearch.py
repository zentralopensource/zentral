import unittest
from zentral.core.stores.backends.elasticsearch import EventStore as ElasticsearchEventStore
from . import BaseTestEventStore


class TestElasticsearchEventStore(unittest.TestCase, BaseTestEventStore):
    TEST_INDEX = 'zentral-tests-events'

    def setUp(self):
        self.event_store = ElasticsearchEventStore({'servers': ["http://elastic:9200"],
                                                    'index': self.TEST_INDEX,
                                                    'store_name': 'elasticsearch_test'},
                                                   test=True)

    def tearDown(self):
        self.event_store._es.indices.delete(index=self.TEST_INDEX, ignore=[404])
        self.event_store.close()


if __name__ == '__main__':
    unittest.main()
