from unittest.mock import Mock, patch
from django.test import SimpleTestCase
from django.utils.crypto import get_random_string
from accounts.events import EventMetadata, LoginEvent
from zentral.core.stores.backends.syslog import EventStore


class SyslogStoreTestCase(SimpleTestCase):
    def get_store(self, **kwargs):
        for arg, default in (("store_name", get_random_string(12)),
                             ("priority", None),
                             ("facility", None),
                             ("prepend_ecc", None),
                             ("protocol", None),
                             ("host", None),
                             ("port", None)):
            val = kwargs.get(arg)
            if val is None and default is not None:
                kwargs[arg] = default
        return EventStore(kwargs)

    def build_login_event(self, username=None):
        if username is None:
            username = get_random_string(12)
        return LoginEvent(EventMetadata(), {"user": {"username": username}})

    @patch("zentral.core.stores.backends.syslog.socket")
    def test_store(self, syslog_socket):
        mock_socket = Mock()
        mock_socket.connect.return_value = None
        mock_socket.send.return_value = None
        syslog_socket.socket.return_value = mock_socket
        store = self.get_store()
        store.wait_and_configure_if_necessary()
        event = self.build_login_event()
        store.store(event)
        mock_socket.connect.assert_called_once()
        mock_socket.send.assert_called_once()
