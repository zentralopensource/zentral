from unittest.mock import Mock
from django.test import TestCase
from django.utils.crypto import get_random_string
from accounts.models import Group
from zentral.core.stores.backends.http import HTTPStore, HTTPStoreSerializer
from .utils import build_login_event, force_store


class HttpStoreTestCase(TestCase):
    maxDiff = None

    def get_store(self, **kwargs):
        for arg, default in (("endpoint_url", "https://www.example.com"),
                             ("verify_tls", True),
                             ("username", "yolo"),
                             ("password", "fomo"),
                             ("headers", [{"name": "X-Yolo", "value": "Fomo"}]),
                             ("concurrency", 1),
                             ("request_timeout", 120),
                             ("max_retries", 3)):
            if arg not in kwargs:
                kwargs[arg] = default
        return force_store(backend_kwargs=kwargs)

    # backend model

    def test_backend_get_backend(self):
        store = self.get_store()
        self.assertIsInstance(store, HTTPStore)
        store2 = store.instance.get_backend(load=True)
        self.assertIsInstance(store2, HTTPStore)
        self.assertEqual(store2.instance, store.instance)

    def test_backend_editing(self):
        store = self.get_store()
        self.assertIsNone(store.instance.provisioning_uid)
        self.assertTrue(store.instance.can_be_deleted())
        self.assertTrue(store.instance.can_be_updated())

    def test_provisioned_backend_editing(self):
        store = self.get_store()
        store.instance.provisioning_uid = get_random_string(12)
        store.instance.save()
        self.assertFalse(store.instance.can_be_deleted())
        self.assertFalse(store.instance.can_be_updated())

    def test_backend_encrypted_kwargs(self):
        store = self.get_store()
        self.assertEqual(
            store.instance.backend_kwargs,
            {'endpoint_url': 'https://www.example.com',
             'verify_tls': True,
             'username': "yolo",
             'password': "noop$Zm9tbw==",  # "encrypted"
             'headers': [{"name": "X-Yolo", "value": "noop$Rm9tbw=="}],  # "encrypted"
             'concurrency': 1,
             'request_timeout': 120,
             'max_retries': 3}
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
             'backend': 'HTTP',
             'backend_kwargs': {
                 'concurrency': 1,
                 'endpoint_url': 'https://www.example.com',
                 'headers': [{'name': 'X-Yolo',
                              'value_hash': '23abd07bdc188e0aec2bffd0f1bd0cd130df9a53e68668c467463d55c705e53a'}],
                 'max_retries': 3,
                 'password_hash': '48ffcddb8b19a5f98d4b1b8c08b4024b12b6f24affeb50b1265aed528a2dd671',
                 'request_timeout': 120,
                 'username': 'yolo',
                 'verify_tls': True
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

    def test_event_serialization(self):
        username = get_random_string(12)
        event = build_login_event(username)
        self.assertEqual(
            self.get_store().client._serialize_event(event),
            {'created_at': event.metadata.created_at.isoformat(),
             'id': str(event.metadata.uuid),
             'index': 0,
             'namespace': 'zentral',
             'tags': ['zentral'],
             'type': 'zentral_login',
             'zentral': {'user': {'username': username}}}
        )

    def test_dict_event_serialization(self):
        username = get_random_string(12)
        event = build_login_event(username)
        self.assertEqual(
            self.get_store().client._serialize_event(event.serialize()),
            {'created_at': event.metadata.created_at.isoformat(),
             'id': str(event.metadata.uuid),
             'index': 0,
             'namespace': 'zentral',
             'tags': ['zentral'],
             'type': 'zentral_login',
             'zentral': {'user': {'username': username}}}
        )

    # event storage

    def test_store(self):
        mock_response = Mock()
        mock_response.ok = True
        mock_post = Mock(return_value=mock_response)
        store = self.get_store()
        store.client.session.post = mock_post
        event = build_login_event()
        store.store(event)
        mock_post.assert_called_once()

    # serializer

    def test_serializer_missing_fields(self):
        s = HTTPStoreSerializer(data={})
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"endpoint_url": ["This field is required."]}
        )

    def test_serializer_invalid_fields(self):
        s = HTTPStoreSerializer(data={
            "endpoint_url": "https://",
            "request_timeout": 3600,
            "max_retries": 42
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"endpoint_url": ["Invalid URL netloc"],
             "request_timeout": ["Ensure this value is less than or equal to 600."],
             "max_retries": ["Ensure this value is less than or equal to 5."]},
        )

    def test_serializer_incorrect_endpoint_url_type(self):
        s = HTTPStoreSerializer(data={"endpoint_url": 1})
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"endpoint_url": ["Incorrect type"]},
        )

    def test_serializer_invalid_endpoint_url_scheme(self):
        s = HTTPStoreSerializer(data={"endpoint_url": "ftp://yolo"})
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"endpoint_url": ["Invalid URL scheme"]},
        )

    def test_serializer_missing_password(self):
        s = HTTPStoreSerializer(data={"endpoint_url": "https://www.example.com", "username": "yolo"})
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"password": ["Required when username is set"]}
        )

    def test_serializer_missing_username(self):
        s = HTTPStoreSerializer(data={"endpoint_url": "https://www.example.com", "password": "fomo"})
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"username": ["Required when password is set"]}
        )

    def test_serializer_auth_conflict(self):
        s = HTTPStoreSerializer(data={
            "endpoint_url": "https://www.example.com",
            "username": "yolo",
            "password": "fomo",
            "headers": [{"name": "Authorization", "value": "Bearer yolofomo"}],
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"non_field_errors": ["Basic Auth and Authorization header cannot be both set"]},
        )

    def test_serializer_defaults(self):
        s = HTTPStoreSerializer(data={"endpoint_url": "https://www.example.com"})
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {'endpoint_url': 'https://www.example.com',
             'verify_tls': True,
             'username': None,
             'password': None,
             'concurrency': 1,
             'request_timeout': 120,
             'max_retries': 3}
        )

    def test_serializer_full(self):
        s = HTTPStoreSerializer(data={
            "endpoint_url": "https://www.example.com",
            "verify_tls": False,
            "username": "yolo",
            "password": "fomo",
            "headers": [{"name": "X-Yolo", "value": "Fomo"}],
            "concurrency": 2,
            "request_timeout": 42,
            "max_retries": 2,
        })
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {'endpoint_url': 'https://www.example.com',
             'verify_tls': False,
             'username': "yolo",
             'password': "fomo",
             'headers': [{"name": "X-Yolo", "value": "Fomo"}],
             'concurrency': 2,
             'request_timeout': 42,
             'max_retries': 2}
        )
