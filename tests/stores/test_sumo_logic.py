from unittest.mock import Mock
from django.test import SimpleTestCase
from django.utils.crypto import get_random_string
from accounts.events import EventMetadata, LoginEvent
from zentral.core.exceptions import ImproperlyConfigured
from zentral.core.stores.backends.sumo_logic import EventStore


class SumoLogicStoreTestCase(SimpleTestCase):
    def get_store(self, collector_url="https://collectors.us.sumologic.com/receiver/v1/http/yolo", batch_size=1):
        kwargs = {"store_name": get_random_string(12),
                  "batch_size": batch_size}
        if collector_url:
            kwargs["collector_url"] = collector_url
        return EventStore(kwargs)

    def build_login_event(self, username=None):
        if username is None:
            username = get_random_string(12)
        return LoginEvent(EventMetadata(), {"user": {"username": username}})

    def test_improperly_configured(self):
        with self.assertRaises(ImproperlyConfigured) as cm:
            self.get_store(collector_url=None)
        self.assertEqual(cm.exception.args[0], "Missing collector_url")

    def test_event_serialization(self):
        username = get_random_string(12)
        event = self.build_login_event(username)
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
        event = self.build_login_event(username)
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

    def test_store(self):
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_post = Mock(return_value=mock_response)
        store = self.get_store()
        store.session.post = mock_post
        event = self.build_login_event()
        store.store(event)
        mock_post.assert_called_once()
        mock_response.raise_for_status.assert_called_once()

    def test_bulk_store_batch_size_error(self):
        store = self.get_store()
        events = [self.build_login_event() for i in range(2)]
        with self.assertRaises(RuntimeError) as cm:
            store.bulk_store(events)
        self.assertEqual(cm.exception.args[0], "bulk_store is not available when batch_size < 2")

    def test_bulk_store(self):
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_post = Mock(return_value=mock_response)
        store = self.get_store(batch_size=10)
        store.session.post = mock_post
        events = [self.build_login_event() for i in range(2)]
        response = store.bulk_store(events)
        mock_post.assert_called_once()
        mock_response.raise_for_status.assert_called_once()
        self.assertEqual(
            response,
            [(str(evt.metadata.uuid), evt.metadata.index) for evt in events]
        )
