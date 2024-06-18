from unittest.mock import Mock
from django.test import SimpleTestCase
from django.utils.crypto import get_random_string
from accounts.events import EventMetadata, LoginEvent
from zentral.core.stores.backends.humio import EventStore


class HumioStoreTestCase(SimpleTestCase):
    def get_store(self, **kwargs):
        for arg, default in (("store_name", get_random_string(12)),
                             ("base_url", "https://example.com"),
                             ("ingest_token", "123")):
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
            [{'events': [{'attributes': {'id': str(event.metadata.uuid),
                                         'index': 0,
                                         'namespace': 'zentral',
                                         'tags': ['zentral'],
                                         'zentral': {'user': {'username': username}}},
                          'timestamp': event.metadata.created_at.isoformat()[:-3] + "Z"}],
              'tags': {'event_type': 'zentral_login'}}]
        )

    def test_dict_event_serialization(self):
        username = get_random_string(12)
        event = self.build_login_event(username)
        self.assertEqual(
            self.get_store()._serialize_event(event.serialize()),
            [{'events': [{'attributes': {'id': str(event.metadata.uuid),
                                         'index': 0,
                                         'namespace': 'zentral',
                                         'tags': ['zentral'],
                                         'zentral': {'user': {'username': username}}},
                          'timestamp': event.metadata.created_at.isoformat()[:-3] + "Z"}],
              'tags': {'event_type': 'zentral_login'}}]
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
