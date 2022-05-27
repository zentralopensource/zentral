from unittest.mock import Mock
from django.test import SimpleTestCase
from django.utils.crypto import get_random_string
from accounts.events import EventMetadata, LoginEvent
from zentral.core.stores.backends.http import EventStore


class HttpStoreTestCase(SimpleTestCase):
    def get_store(self, **kwargs):
        for arg, default in (("store_name", get_random_string(12)),
                             ("endpoint_url", "https://example.com"),
                             ("verify_tls", None),
                             ("headers", None),
                             ("username", None),
                             ("password", None)):
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
        event = self.build_login_event(username)
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

    def test_store(self):
        mock_response = Mock()
        mock_response.ok = True
        mock_post = Mock(return_value=mock_response)
        store = self.get_store()
        store.client.session.post = mock_post
        event = self.build_login_event()
        store.store(event)
        mock_post.assert_called_once()
