from unittest.mock import Mock
from django.test import SimpleTestCase
from django.utils.crypto import get_random_string
from accounts.events import EventMetadata, LoginEvent
from zentral.core.stores.backends.datadog import EventStore


class DatadogStoreTestCase(SimpleTestCase):
    def get_store(self, **kwargs):
        for arg, default in (("store_name", get_random_string(12)),
                             ("site", "datadoghq.com"),
                             ("service", None),
                             ("source", None),
                             ("api_key", "123"),
                             ("application_key", "456")):
            val = kwargs.get(arg)
            if val is None and default is not None:
                kwargs[arg] = default
        return EventStore(kwargs)

    def build_login_event(self, username=None):
        if username is None:
            username = get_random_string(12)
        return LoginEvent(EventMetadata(), {"user": {"username": username}})

    def test_event_serialization(self):
        username = get_random_string(12)
        event = self.build_login_event(username)
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
        event = self.build_login_event(username)
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

    def test_store(self):
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_post = Mock(return_value=mock_response)
        store = self.get_store()
        store._session.post = mock_post
        event = self.build_login_event()
        store.store(event)
        mock_post.assert_called_once()
        mock_response.raise_for_status.assert_called_once()
