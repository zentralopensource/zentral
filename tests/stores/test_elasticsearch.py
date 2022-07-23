from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.core.stores.backends.elasticsearch import EventStore as ElasticsearchEventStore
from . import BaseTestEventStore


class TestElasticsearchEventStore(TestCase, BaseTestEventStore):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.index = get_random_string(12).lower()
        cls.event_store = ElasticsearchEventStore(
            {'servers': ["http://elastic:9200"],
             'index': cls.index,
             'store_name': 'elasticsearch_test',
             'aws_auth': {
                 'access_id': 'testing',
                 'secret_key': 'testing',
                 'region': 'us-east-1'
             }},
            test=True
        )

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls.event_store._es.indices.delete(index=cls.index, ignore=[404])
        cls.event_store.close()
