from django.test import SimpleTestCase
from django.utils.crypto import get_random_string
from accounts.events import EventMetadata, LoginEvent
from zentral.conf.config import ConfigDict
from zentral.core.exceptions import ImproperlyConfigured
from zentral.core.stores.backends.elasticsearch import EventStore


class TestElasticsearchStoreConf(SimpleTestCase):
    @staticmethod
    def build_login_event(routing_key=None):
        return LoginEvent(EventMetadata(routing_key=routing_key), {"user": {"username": get_random_string(12)}})

    def test_index_and_indices(self):
        with self.assertRaises(ImproperlyConfigured) as cm:
            EventStore(ConfigDict({
                'servers': ["http://elastic:9200"],
                'indices': {"un": {}},
                'index': 'zentral-events',
                'store_name': 'yolo'
            }))
        self.assertEqual(cm.exception.args[0], 'index and indices cannot be both set')

    def test_indices_not_a_mapping(self):
        with self.assertRaises(ImproperlyConfigured) as cm:
            EventStore(ConfigDict({
                'servers': ["http://elastic:9200"],
                'indices': "yolo",
                'store_name': 'yolo'
            }))
        self.assertEqual(cm.exception.args[0], 'indices must be a Mapping')

    def test_indices_missing_or_invalid_index_priority(self):
        with self.assertRaises(ImproperlyConfigured) as cm:
            EventStore(ConfigDict({
                'servers': ["http://elastic:9200"],
                'indices': {"un": {}},
                'store_name': 'yolo'
            }))
        self.assertEqual(cm.exception.args[0], 'missing or invalid index priority')

    def test_indices_duplicated_index_priority(self):
        with self.assertRaises(ImproperlyConfigured) as cm:
            EventStore(ConfigDict({
                'servers': ["http://elastic:9200"],
                'indices': {"un": {"priority": 10}, "deux": {"priority": 10}},
                'store_name': 'yolo'
            }))
        self.assertEqual(cm.exception.args[0], 'all indices must have a different priority')

    def test_indices_invalid_event_filters(self):
        with self.assertRaises(ImproperlyConfigured) as cm:
            EventStore(ConfigDict({
                'servers': ["http://elastic:9200"],
                'indices': {"un": {"priority": 20,
                                   "included_event_filters": "yolo"},
                            "deux": {"priority": 10}},
                'store_name': 'yolo'
            }))
        self.assertEqual(cm.exception.args[0], "invalid event filters for index 'un'")

    def test_default_index_filtered(self):
        with self.assertRaises(ImproperlyConfigured) as cm:
            EventStore(ConfigDict({
                'servers': ["http://elastic:9200"],
                'indices': {"un": {"priority": 20,
                                   "included_event_filters": [{"event_type": ["yolo"]}]},
                            "deux": {"priority": 10,
                                     "included_event_filters": [{"event_type": ["fomo"]}]}},
                'store_name': 'yolo'
            }))
        self.assertEqual(cm.exception.args[0], "default index 'deux' (lowest priority) cannot be filtered")

    def test_no_index_configured(self):
        with self.assertRaises(ImproperlyConfigured) as cm:
            EventStore(ConfigDict({
                'servers': ["http://elastic:9200"],
                'store_name': 'yolo'
            }))
        self.assertEqual(cm.exception.args[0], "no index configured")

    def test_missing_read_index(self):
        with self.assertRaises(ImproperlyConfigured) as cm:
            EventStore(ConfigDict({
                'servers': ["http://elastic:9200"],
                'indices': {"un": {"priority": 20,
                                   "included_event_filters": [{"event_type": ["yolo"]}]},
                            "deux": {"priority": 10}},
                'store_name': 'yolo'
            }))
        self.assertEqual(cm.exception.args[0], "missing read index")

    def test_kwargs_basic_auth(self):
        kwargs = EventStore._get_client_kwargs(ConfigDict({
            'servers': ["http://elastic:9200"],
            'index': 'zentral-events',
            'store_name': 'yolo',
            'basic_auth': ("user", "password"),
        }))
        self.assertEqual(
            kwargs,
            {'hosts': [{'host': 'elastic',
                        'port': 9200,
                        'scheme': 'http'}],
             'basic_auth': ("user", "password")}
        )

    def test_kwargs_default_verify_certs(self):
        kwargs = EventStore._get_client_kwargs(ConfigDict({
            'servers': ["https://elastic:9200"],
            'index': 'zentral-events',
            'store_name': 'yolo'
        }))
        self.assertEqual(
            kwargs,
            {'hosts': [{'host': 'elastic',
                        'port': 9200,
                        'scheme': 'https',
                        'use_ssl': True}],
             'verify_certs': True}
        )

    def test_kwargs_override_verify_certs(self):
        kwargs = EventStore._get_client_kwargs(ConfigDict({
            'servers': ["https://elastic:9200"],
            'index': 'zentral-events',
            'store_name': 'yolo',
            'verify_certs': False,
            'ssl_show_warn': False,
        }))
        self.assertEqual(
            kwargs,
            {'hosts': [{'host': 'elastic',
                        'port': 9200,
                        'scheme': 'https',
                        'use_ssl': True}],
             'verify_certs': False,
             'ssl_show_warn': False}
        )

    def test_one_index_get_event_index(self):
        store_index = get_random_string(12)
        store = EventStore(ConfigDict({
            'servers': ["http://elastic:9200"],
            'index': store_index,
            'store_name': 'yolo'
        }))
        event = self.build_login_event(routing_key="jomo")
        self.assertEqual(store._get_event_index(event.serialize()), store_index)

    def test_one_index_serialize_event(self):
        store_index = get_random_string(12)
        store = EventStore(ConfigDict({
            'servers': ["http://elastic:9200"],
            'index': store_index,
            'store_name': 'yolo'
        }))
        store.use_mapping_types = False
        event = self.build_login_event(routing_key="jomo")
        index, es_doc_type, es_event_d = store._serialize_event(event)
        self.assertEqual(index, store_index)
        self.assertEqual(es_doc_type, "doc")
        self.assertEqual(es_event_d["type"], "zentral_login")
        self.assertEqual(es_event_d["tags"], ["zentral"])
        self.assertEqual(es_event_d["routing_key"], "jomo")

    def test_indices_get_event_index_1(self):
        store = EventStore(ConfigDict({
            'servers': ["http://elastic:9200"],
            'indices': {"un": {"priority": 20,
                               "included_event_filters": [{"routing_key": ["yolo"]}]},
                        "deux": {"priority": 10}},
            'read_index': "all_integers",
            'store_name': 'yolo'
        }))
        event = self.build_login_event(routing_key="jomo")
        self.assertEqual(store._get_event_index(event.serialize()), "deux")

    def test_indices_get_event_index_2(self):
        store = EventStore(ConfigDict({
            'servers': ["http://elastic:9200"],
            'indices': {"un": {"priority": 20,
                               "included_event_filters": [{"routing_key": ["yolo"]}]},
                        "deux": {"priority": 10}},
            'read_index': "all_integers",
            'store_name': 'yolo'
        }))
        event = self.build_login_event(routing_key="yolo")
        self.assertEqual(store._get_event_index(event.serialize()), "un")
