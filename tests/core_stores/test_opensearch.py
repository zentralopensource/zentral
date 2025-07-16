from django.test import TestCase
from django.utils.crypto import get_random_string
from accounts.models import Group
from zentral.core.stores.backends.all import StoreBackend
from zentral.core.stores.backends.opensearch import OpenSearchStore, OpenSearchStoreSerializer
from .utils import force_store
from . import BaseTestStore


class TestOpenSearchStoreStorage(TestCase, BaseTestStore):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.index = get_random_string(12).lower()
        # TODO: we are testing OpenSearch against Elasticsearch
        # Setup a propoer OpenSearch server?
        cls.store = force_store(
            backend=StoreBackend.OpenSearch,
            backend_kwargs={
                'hosts': ["http://elastic:9200"],
                'index': cls.index,
                'batch_size': 100,
                'number_of_shards': 1,
                'number_of_replicas': 0
            }
        )

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls.store._client.indices.delete(index=cls.index, ignore=[404])
        cls.store.close()


class TestOpenSearchStore(TestCase):
    maxDiff = None

    def get_store(self, **kwargs):
        for arg, default in (("hosts", ["http://opensearch:9200"]),
                             ("verify_certs", True),
                             ("ssl_show_warn", True),
                             ("aws_auth", {"region_name": "eu-central-1",
                                           "aws_access_key_id": "yolo",
                                           "aws_secret_access_key": "fomo"}),
                             ("username", None),
                             ("password", None),
                             ("batch_size", 42),
                             ("index", "zentral-events"),
                             ("number_of_shards", 1),
                             ("number_of_replicas", 0),
                             ("kibana_discover_url", "https://kibana"),
                             ("kibana_index_pattern_uuid", "00000000-0000-0000-0000-000000000000")):
            if arg not in kwargs:
                kwargs[arg] = default
        return force_store(backend=StoreBackend.OpenSearch, backend_kwargs=kwargs)

    # backend model

    def test_backend_get_backend(self):
        store = self.get_store()
        self.assertIsInstance(store, OpenSearchStore)
        store2 = store.instance.get_backend(load=True)
        self.assertIsInstance(store2, OpenSearchStore)
        self.assertEqual(store2.instance, store.instance)

    def test_backend_encrypted_kwargs(self):
        store = self.get_store()
        self.assertEqual(
            store.instance.backend_kwargs,
            {'hosts': ["http://opensearch:9200"],
             'verify_certs': True,
             'ssl_show_warn': True,
             'aws_auth': {
                 'region_name': 'eu-central-1',
                 'aws_access_key_id': 'yolo',
                 'aws_secret_access_key': 'noop$Zm9tbw==',  # "encrypted"
             },
             'username': None,
             'password': None,
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
             'backend': 'OPENSEARCH',
             'backend_kwargs': {
                 'hosts': ['http://opensearch:9200'],
                 'verify_certs': True,
                 'ssl_show_warn': True,
                 'aws_auth': {
                     'region_name': 'eu-central-1',
                     'aws_access_key_id': 'yolo',
                     'aws_secret_access_key_hash': '48ffcddb8b19a5f98d4b1b8c08b4024b12b6f24affeb50b1265aed528a2dd671',
                 },
                 'username': None,
                 'password_hash': None,
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

    # serializer

    def test_serializer_missing_aws_secret_access_key(self):
        s = OpenSearchStoreSerializer(data={
            "hosts": ["http://opensearch:9200"],
            "index": "zentral-events",
            "aws_auth": {
                "region_name": "eu-central-1",
                "aws_access_key_id": "yolo",
            }
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"aws_auth": {"aws_secret_access_key": ["This field is required"]}}
        )

    def test_serializer_missing_aws_access_key_id(self):
        s = OpenSearchStoreSerializer(data={
            "hosts": ["http://opensearch:9200"],
            "index": "zentral-events",
            "aws_auth": {
                "region_name": "eu-central-1",
                "aws_secret_access_key": "fomo",
            }
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"aws_auth": {"aws_access_key_id": ["This field is required"]}}
        )

    def test_serializer_basic_auth_aws_auth_conflict(self):
        s = OpenSearchStoreSerializer(data={
            "hosts": ["http://opensearch:9200"],
            "index": "zentral-events",
            "aws_auth": {
                "region_name": "eu-central-1",
                "aws_access_key_id": "yolo",
                "aws_secret_access_key": "fomo",
            },
            "username": "username",
            "password": "password",
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"aws_auth": ["Cannot be used with basic auth"]}
        )
