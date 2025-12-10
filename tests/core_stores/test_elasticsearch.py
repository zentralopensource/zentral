from django.test import TestCase
from django.utils.crypto import get_random_string
from accounts.models import Group
from zentral.core.stores.backends.all import StoreBackend
from zentral.core.stores.backends.es_os_base import ESOSStoreSerializer
from zentral.core.stores.backends.elasticsearch import ElasticsearchStore
from .utils import build_login_event, force_store
from . import BaseTestStore


class TestElasticsearchStoreStorage(TestCase, BaseTestStore):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.index = get_random_string(12).lower()
        cls.store = force_store(
            backend=StoreBackend.Elasticsearch,
            backend_kwargs={
                "hosts": ["http://elastic:9200"],
                "index": cls.index,
                "batch_size": 100,
                "number_of_shards": 1,
                "number_of_replicas": 0,
            }
        )

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls.store._client.options(ignore_status=404).indices.delete(index=cls.index)
        cls.store.close()


class TestElasticsearchStore(TestCase):
    def get_store(self, **kwargs):
        for arg, default in (("hosts", ["http://elastic:9200"]),
                             ("verify_certs", True),
                             ("ssl_show_warn", True),
                             ("username", "yolo"),
                             ("password", "fomo"),
                             ("batch_size", 42),
                             ("index", "zentral-events"),
                             ("number_of_shards", 1),
                             ("number_of_replicas", 0),
                             ("kibana_discover_url", "https://kibana"),
                             ("kibana_index_pattern_uuid", "00000000-0000-0000-0000-000000000000")):
            val = kwargs.get(arg)
            if val is None and default is not None:
                kwargs[arg] = default
        return force_store(backend=StoreBackend.Elasticsearch, backend_kwargs=kwargs)

    # backend model

    def test_backend_get_backend(self):
        store = self.get_store()
        self.assertIsInstance(store, ElasticsearchStore)
        store2 = store.instance.get_backend(load=True)
        self.assertIsInstance(store2, ElasticsearchStore)
        self.assertEqual(store2.instance, store.instance)

    def test_backend_encrypted_kwargs(self):
        store = self.get_store()
        self.assertEqual(
            store.instance.backend_kwargs,
            {'hosts': ["http://elastic:9200"],
             'verify_certs': True,
             'ssl_show_warn': True,
             'username': "yolo",
             'password': "noop$Zm9tbw==",  # "encrypted"
             'batch_size': 42,
             'index': "zentral-events",
             'number_of_shards': 1,
             'number_of_replicas': 0,
             'kibana_discover_url': "https://kibana",
             'kibana_index_pattern_uuid': "00000000-0000-0000-0000-000000000000"}
        )

    def test_backend_serialize_for_event(self):
        store = self.get_store()
        store.instance.provisioning_uid = get_random_string(12)
        store.instance.save()
        role = Group.objects.create(name=get_random_string(12))
        store.instance.events_url_authorized_roles.add(role)
        self.assertEqual(
            store.instance.serialize_for_event(),
            {'admin_console': False,
             'backend': 'ELASTICSEARCH',
             'backend_kwargs': {
                 'hosts': ['http://elastic:9200'],
                 'verify_certs': True,
                 'ssl_show_warn': True,
                 'username': 'yolo',
                 'password_hash': '48ffcddb8b19a5f98d4b1b8c08b4024b12b6f24affeb50b1265aed528a2dd671',
                 'batch_size': 42,
                 'index': 'zentral-events',
                 'number_of_shards': 1,
                 'number_of_replicas': 0,
                 'kibana_discover_url': 'https://kibana',
                 'kibana_index_pattern_uuid': '00000000-0000-0000-0000-000000000000',
             },
             'created_at': store.instance.created_at,
             'description': '',
             'event_filters': {},
             'events_url_authorized_roles': [{'name': role.name, 'pk': role.pk}],
             'name': store.instance.name,
             'pk': str(store.instance.pk),
             'provisioning_uid': store.instance.provisioning_uid,
             'updated_at': store.instance.updated_at}
        )

    # event serialization

    def test_simple_index(self):
        store = force_store(
            backend=StoreBackend.Elasticsearch,
            backend_kwargs={
                "hosts": ["https://elastic:9200"],
                "index": "zentral-events",
            }
        )
        self.assertEqual(store.index, "zentral-events")
        self.assertEqual(store.read_index, "zentral-events")
        self.assertIsNone(store.index_mappings)
        login_event = build_login_event(routing_key="yolo")
        index, _, _ = store._serialize_event(login_event)
        self.assertEqual(index, "zentral-events")

    def test_index_mappings(self):
        store = force_store(
            backend=StoreBackend.Elasticsearch,
            backend_kwargs={
                "hosts": ["https://elastic:9200"],
                "indices": [
                    {"name": "zentral-yolo", "priority": 10,
                     "included_event_filters": [{"routing_key": ["yolo"]}]},
                    {"name": "zentral-default", "priority": 1},
                ],
                "read_index": "zentral-events",
            }
        )
        self.assertIsNone(store.index)
        self.assertEqual(store.read_index, "zentral-events")
        login_event = build_login_event(routing_key="yolo")
        index, _, _ = store._serialize_event(login_event)
        self.assertEqual(index, "zentral-yolo")
        login_event = build_login_event(routing_key="fomo")
        index, _, _ = store._serialize_event(login_event)
        self.assertEqual(index, "zentral-default")

    # serializer

    def test_serializer_missing_fields(self):
        s = ESOSStoreSerializer(data={})
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"hosts": ["This field is required."]}
        )

    def test_serializer_no_index_indices_required(self):
        s = ESOSStoreSerializer(data={"hosts": ["http://elastic:9200"]})
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"indices": ["Required when index is empty"]}
        )

    def test_serializer_indices_index_conflict(self):
        s = ESOSStoreSerializer(data={
            "hosts": ["http://elastic:9200"],
            "index": "zentral-events",
            "indices": [
                {"name": "zentral-yolo", "priority": 10,
                 "included_event_filters": [{"routing_key": ["yolo"]}]},
                {"name": "zentral-default", "priority": 1},
            ]
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"index": ["Cannot be set when multiple indices are configured"]}
        )

    def test_serializer_indices_same_priority_error(self):
        s = ESOSStoreSerializer(data={
            "hosts": ["http://elastic:9200"],
            "indices": [
                {"name": "zentral-yolo", "priority": 10,
                 "included_event_filters": [{"routing_key": ["yolo"]}]},
                {"name": "zentral-default", "priority": 10},
            ]
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"indices": ["All indices must have a different priority"]}
        )

    def test_serializer_indices_same_name_error(self):
        s = ESOSStoreSerializer(data={
            "hosts": ["http://elastic:9200"],
            "indices": [
                {"name": "zentral-yolo", "priority": 10,
                 "included_event_filters": [{"routing_key": ["yolo"]}]},
                {"name": "zentral-yolo", "priority": 1},
            ]
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"indices": ["All indices must have a different name"]}
        )

    def test_serializer_indices_default_index_filters_error(self):
        s = ESOSStoreSerializer(data={
            "hosts": ["http://elastic:9200"],
            "indices": [
                {"name": "zentral-yolo", "priority": 10,
                 "included_event_filters": [{"routing_key": ["yolo"]}]},
                {"name": "zentral-default", "priority": 1,
                 "excluded_event_filters": [{"tags": ["un", "deux"]}]},
            ]
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"indices": ["Default index zentral-default (lowest priority) cannot be filtered"]}
        )

    def test_serializer_indices_read_index_required(self):
        s = ESOSStoreSerializer(data={
            "hosts": ["http://elastic:9200"],
            "indices": [
                {"name": "zentral-yolo", "priority": 10,
                 "included_event_filters": [{"routing_key": ["yolo"]}]},
                {"name": "zentral-default", "priority": 1},
            ]
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"read_index": ["Required when multiple indices are configured"]}
        )

    def test_serializer_invalid_fields(self):
        s = ESOSStoreSerializer(data={
            "hosts": ["https://"],
            "batch_size": 1234,
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"hosts": {0: ["Invalid URL netloc"]},
             "batch_size": ["Ensure this value is less than or equal to 500."]},
        )

    def test_serializer_missing_password(self):
        s = ESOSStoreSerializer(data={"hosts": ["http://elastic:9200"], "username": "yolo"})
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"password": ["Required when username is set"]}
        )

    def test_serializer_missing_username(self):
        s = ESOSStoreSerializer(data={"hosts": ["http://elastic:9200"], "password": "fomo"})
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"username": ["Required when password is set"]}
        )

    def test_serializer_defaults(self):
        s = ESOSStoreSerializer(data={"hosts": ["https://elastic:9200"],
                                      "index": "zentral-events"})
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {'hosts': ['https://elastic:9200'],
             'verify_certs': True,
             'ssl_show_warn': True,
             'username': None,
             'password': None,
             'batch_size': 1,
             'index': 'zentral-events',
             'number_of_shards': 1,
             'number_of_replicas': 0}
        )

    def test_serializer_full(self):
        s = ESOSStoreSerializer(data={
            "hosts": ["https://elastic:9200"],
            "verify_certs": False,
            "ssl_show_warn": False,
            "indices": [
                {"name": "zentral-yolo", "priority": 10,
                 "included_event_filters": [{"routing_key": ["yolo"]}]},
                {"name": "zentral-default", "priority": 1},
            ],
            "read_index": "zentral-events",
            "username": "yolo",
            "password": "fomo",
            "batch_size": 42,
            "number_of_shards": 4,
            "number_of_replicas": 1,
            "kibana_discover_url": "https://kibana",
            "kibana_index_pattern_uuid": "00000000-0000-0000-0000-000000000000",
        })
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {'batch_size': 42,
             'hosts': ['https://elastic:9200'],
             'indices': [{'included_event_filters': [{'routing_key': ['yolo']}],
                          'name': 'zentral-yolo',
                          'priority': 10},
                         {'name': 'zentral-default', 'priority': 1}],
             'kibana_discover_url': 'https://kibana',
             'kibana_index_pattern_uuid': '00000000-0000-0000-0000-000000000000',
             'number_of_replicas': 1,
             'number_of_shards': 4,
             'password': 'fomo',
             'read_index': 'zentral-events',
             'ssl_show_warn': False,
             'username': 'yolo',
             'verify_certs': False}
        )
