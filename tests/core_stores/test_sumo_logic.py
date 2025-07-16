from unittest.mock import Mock
from django.test import TestCase
from django.utils.crypto import get_random_string
from accounts.models import Group
from zentral.core.stores.backends.all import StoreBackend
from zentral.core.stores.backends.sumo_logic import SumoLogicStore, SumoLogicStoreSerializer
from .utils import build_login_event, force_store


class SumoLogicStoreTestCase(TestCase):
    maxDiff = None

    def get_store(self, **kwargs):
        for arg, default in (
            ("collector_url", "https://collectors.us.sumologic.com/receiver/v1/http/yolo"),
            ("batch_size", 17),
        ):
            val = kwargs.get(arg)
            if val is None and default is not None:
                kwargs[arg] = default
        return force_store(backend=StoreBackend.SumoLogic, backend_kwargs=kwargs)

    # backend model

    def test_backend_get_backend(self):
        store = self.get_store()
        self.assertIsInstance(store, SumoLogicStore)
        store2 = store.instance.get_backend(load=True)
        self.assertIsInstance(store2, SumoLogicStore)
        self.assertEqual(store2.instance, store.instance)

    def test_backend_encrypted_kwargs(self):
        store = self.get_store()
        self.assertEqual(
            store.instance.backend_kwargs,
            {'collector_url': 'noop$aHR0cHM6Ly9jb2xsZWN0b3JzLnVzLnN1bW9sb2dpYy5jb20vcmVjZWl2ZXIvdjEvaHR0cC95b2xv',
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
             'backend': 'SUMO_LOGIC',
             'backend_kwargs': {
                 'collector_url_hash': "0fc69646d9b87df28701f8a6ec2cdd0a1aec97124cf1999c94556d6acc40279e",
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
             'zentral': {'user': {'username': username}}}
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
             'zentral': {'user': {'username': username}}}
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
        s = SumoLogicStoreSerializer(data={})
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"collector_url": ["This field is required."]}
        )

    def test_serializer_invalid_fields(self):
        s = SumoLogicStoreSerializer(data={
            "collector_url": "https://yolo",
            "batch_size": 1234,
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"collector_url": ["Enter a valid URL."],
             "batch_size": ["Ensure this value is less than or equal to 100."]}
        )

    def test_serializer_defaults(self):
        s = SumoLogicStoreSerializer(data={
            "collector_url": "https://www.example.com",
        })
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {"collector_url": "https://www.example.com",
             "batch_size": 1},
        )

    def test_serializer_full(self):
        s = SumoLogicStoreSerializer(data={
            "collector_url": "https://www.example.com",
            "batch_size": 17,
        })
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {"collector_url": "https://www.example.com",
             "batch_size": 17},
        )
