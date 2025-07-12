from unittest.mock import Mock
from django.test import TestCase
from django.utils.crypto import get_random_string
from accounts.models import Group
from zentral.core.stores.backends.all import StoreBackend
from zentral.core.stores.backends.panther import PantherStore, PantherStoreSerializer
from .utils import build_login_event, force_store


class PantherStoreTestCase(TestCase):
    maxDiff = None

    def get_store(self, **kwargs):
        for arg, default in (
            ("endpoint_url", "https://www.example.com"),
            ("bearer_token", "123"),
            ("batch_size", 17),
        ):
            if arg not in kwargs:
                kwargs[arg] = default
        return force_store(backend=StoreBackend.Panther, backend_kwargs=kwargs)

    # backend model

    def test_backend_get_backend(self):
        store = self.get_store()
        self.assertIsInstance(store, PantherStore)
        store2 = store.instance.get_backend(load=True)
        self.assertIsInstance(store2, PantherStore)
        self.assertEqual(store2.instance, store.instance)

    def test_backend_encrypted_kwargs(self):
        store = self.get_store()
        self.assertEqual(
            store.instance.backend_kwargs,
            {'endpoint_url': 'https://www.example.com',
             'bearer_token': 'noop$MTIz',
             'batch_size': 17},
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
             'backend': 'PANTHER',
             'backend_kwargs': {
                 'endpoint_url': "https://www.example.com",
                 'bearer_token_hash': "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
                 'batch_size': 17,
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
            self.get_store()._serialize_event(event),
            {'created_at': event.metadata.created_at.isoformat(),
             'id': str(event.metadata.uuid),
             'index': 0,
             'namespace': 'zentral',
             'tags': ['zentral'],
             'type': 'zentral_login',
             'payload': {'user': {'username': username}}}
        )

    def test_dict_event_serialization(self):
        username = get_random_string(12)
        event = build_login_event(username)
        self.assertEqual(
            self.get_store()._serialize_event(event.serialize()),
            {'created_at': event.metadata.created_at.isoformat(),
             'id': str(event.metadata.uuid),
             'index': 0,
             'namespace': 'zentral',
             'tags': ['zentral'],
             'type': 'zentral_login',
             'payload': {'user': {'username': username}}}
        )

    # event storage

    def test_store(self):
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_post = Mock(return_value=mock_response)
        store = self.get_store()
        store.session.post = mock_post
        event = build_login_event()
        store.store(event)
        mock_post.assert_called_once()
        mock_response.raise_for_status.assert_called_once()

    def test_bulk_store_batch_size_error(self):
        store = self.get_store(batch_size=1)
        events = [build_login_event() for i in range(2)]
        with self.assertRaises(RuntimeError) as cm:
            store.bulk_store(events)
        self.assertEqual(cm.exception.args[0], "bulk_store is not available when batch_size < 2")

    def test_bulk_store(self):
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_post = Mock(return_value=mock_response)
        store = self.get_store(batch_size=10)
        store.session.post = mock_post
        events = [build_login_event() for i in range(2)]
        response = store.bulk_store(events)
        mock_post.assert_called_once()
        mock_response.raise_for_status.assert_called_once()
        self.assertEqual(
            response,
            [(str(evt.metadata.uuid), evt.metadata.index) for evt in events]
        )

    # serializer

    def test_serializer_missing_fields(self):
        s = PantherStoreSerializer(data={})
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"endpoint_url": ["This field is required."],
             "bearer_token": ["This field is required."]}
        )

    def test_serializer_invalid_fields(self):
        s = PantherStoreSerializer(data={
            "endpoint_url": "https://yolo",
            "bearer_token": "",
            "batch_size": 1234,
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"endpoint_url": ["Enter a valid URL."],
             "bearer_token": ["This field may not be blank."],
             "batch_size": ["Ensure this value is less than or equal to 100."]}
        )

    def test_serializer_defaults(self):
        s = PantherStoreSerializer(data={
            "endpoint_url": "https://www.example.com",
            "bearer_token": "123",
        })
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {"endpoint_url": "https://www.example.com",
             "bearer_token": "123",
             "batch_size": 1},
        )

    def test_serializer_full(self):
        s = PantherStoreSerializer(data={
            "endpoint_url": "https://www.example.com",
            "bearer_token": "123",
            "batch_size": 17,
        })
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {"endpoint_url": "https://www.example.com",
             "bearer_token": "123",
             "batch_size": 17},
        )
