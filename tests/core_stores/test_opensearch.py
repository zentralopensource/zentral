from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.core.stores.backends.opensearch import EventStore as OpenSearchEventStore
from . import BaseTestEventStore


class TestOpensearchEventStore(TestCase, BaseTestEventStore):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.index = get_random_string(12).lower()
        # TODO: we are testing OpenSearch against Elasticsearch
        # Setup a propoer OpenSearch server?
        cls.event_store = OpenSearchEventStore(
            {'servers': ["http://elastic:9200"],
             'index': cls.index,
             'store_name': 'opensearch_test',
             'batch_size': 100},
            test=True
        )

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls.event_store._client.indices.delete(index=cls.index, ignore=[404])
        cls.event_store.close()
