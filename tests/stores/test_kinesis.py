from unittest.mock import Mock
from django.test import SimpleTestCase
from django.utils.crypto import get_random_string
from accounts.events import EventMetadata, LoginEvent
from zentral.core.stores.backends.kinesis import EventStore


class KinesisStoreTestCase(SimpleTestCase):
    def get_store(self, **kwargs):
        for arg, default in (("store_name", get_random_string(12)),
                             ("stream", "123"),
                             ("region_name", "us-east1"),
                             ("aws_access_key_id", "123"),
                             ("aws_secret_access_key", "456")):
            val = kwargs.get(arg)
            if val is None and default is not None:
                kwargs[arg] = default
        return EventStore(kwargs)

    def build_login_event(self, username=None):
        if username is None:
            username = get_random_string(12)
        return LoginEvent(EventMetadata(), {"user": {"username": username}})

    def test_store(self):
        store = self.get_store()
        store.wait_and_configure_if_necessary()
        mock_client = Mock()
        mock_client.put_record.return_value = None
        store.client = mock_client
        event = self.build_login_event()
        store.store(event)
        mock_client.put_record.assert_called_once()
