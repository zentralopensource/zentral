from unittest.mock import Mock
from django.test import TestCase
from django.utils.crypto import get_random_string
from accounts.models import Group
from zentral.core.stores.backends.all import StoreBackend
from zentral.core.stores.backends.datadog import DatadogStore, DatadogStoreSerializer
from .utils import build_login_event, force_store


class DatadogStoreTestCase(TestCase):
    maxDiff = None

    def get_store(self, **kwargs):
        for arg, default in (("site", "datadoghq.com"),
                             ("service", "Zentral"),
                             ("source", "zentral"),
                             ("api_key", "123"),
                             ("application_key", "456")):
            val = kwargs.get(arg)
            if val is None and default is not None:
                kwargs[arg] = default
        return force_store(backend=StoreBackend.Datadog, backend_kwargs=kwargs)

    # backend model

    def test_backend_get_backend(self):
        store = self.get_store()
        self.assertIsInstance(store, DatadogStore)
        store2 = store.instance.get_backend(load=True)
        self.assertIsInstance(store2, DatadogStore)
        self.assertEqual(store2.instance, store.instance)

    def test_backend_encrypted_kwargs(self):
        store = self.get_store()
        self.assertEqual(
            store.instance.backend_kwargs,
            {'site': "datadoghq.com",
             'service': "Zentral",
             'source': "zentral",
             "api_key": "noop$MTIz",
             "application_key": "noop$NDU2"}
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
             'backend': 'DATADOG',
             'backend_kwargs': {
                 'site': 'datadoghq.com',
                 'service': 'Zentral',
                 'source': 'zentral',
                 'api_key_hash': 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3',
                 'application_key_hash': 'b3a8e0e1f9ab1bfe3a36f231f676f78bb30a519d2b21e6c530c0eee8ebb4a5d0',
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
            {'@timestamp': event.metadata.created_at.isoformat(),
             'ddsource': 'zentral',
             'ddtags': 'ztl-tag:zentral',
             'host': 'Zentral',
             'id': str(event.metadata.uuid),
             'index': 0,
             'logger': {'name': 'zentral_login'},
             'namespace': 'zentral',
             'service': 'Zentral',
             'zentral': {'user': {'username': username}}}
        )

    def test_dict_event_serialization(self):
        username = get_random_string(12)
        event = build_login_event(username)
        self.assertEqual(
            self.get_store()._serialize_event(event.serialize()),
            {'@timestamp': event.metadata.created_at.isoformat(),
             'ddsource': 'zentral',
             'ddtags': 'ztl-tag:zentral',
             'host': 'Zentral',
             'id': str(event.metadata.uuid),
             'index': 0,
             'logger': {'name': 'zentral_login'},
             'namespace': 'zentral',
             'service': 'Zentral',
             'zentral': {'user': {'username': username}}}
        )

    # event storage

    def test_store(self):
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_post = Mock(return_value=mock_response)
        store = self.get_store()
        store._session.post = mock_post
        event = build_login_event()
        store.store(event)
        mock_post.assert_called_once()
        mock_response.raise_for_status.assert_called_once()

    # serializer

    def test_serializer_missing_fields(self):
        s = DatadogStoreSerializer(data={})
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"site": ["This field is required."],
             "api_key": ["This field is required."]}
        )

    def test_serializer_invalid_fields(self):
        s = DatadogStoreSerializer(data={
            "site": "yolo",
            "service": "",
            "source": "",
            "api_key": "123",
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"site": ['"yolo" is not a valid choice.'],
             "service": ["This field may not be blank."],
             "source": ["This field may not be blank."]}
        )

    def test_serializer_defaults(self):
        s = DatadogStoreSerializer(data={
            "site": "datadoghq.com",
            "api_key": "123",
        })
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {'site': 'datadoghq.com',
             "service": "Zentral",
             "source": "zentral",
             "api_key": "123"}
        )

    def test_serializer_full(self):
        s = DatadogStoreSerializer(data={
            "site": "datadoghq.com",
            "service": "service",
            "source": "source",
            "api_key": "123",
            "application_key": "456",
        })
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {'site': 'datadoghq.com',
             "service": "service",
             "source": "source",
             "api_key": "123",
             "application_key": "456"}
        )
