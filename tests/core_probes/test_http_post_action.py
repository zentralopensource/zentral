from unittest.mock import patch, Mock
from django.test import TestCase
from zentral.core.events.base import BaseEvent, EventMetadata
from .utils import force_action


class HTTPPostActionTests(TestCase):
    def _create_action(self, kwargs):
        action = force_action(backend_kwargs=kwargs)
        return action.get_backend(load=True)

    def test_no_basic_auth_no_headers(self):
        action_backend = self._create_action({"url": "https://www.example.com/post"})
        self.assertEqual(action_backend.headers, [])
        self.assertIsNone(action_backend.session.auth)
        self.assertEqual(
            action_backend.session.headers,
            {'User-Agent': 'Zentral/unknown',
             'Accept-Encoding': 'gzip, deflate',
             'Accept': '*/*',
             'Connection': 'keep-alive',
             'Content-Type': 'application/json'}
        )

    def test_basic_auth_headers(self):
        action_backend = self._create_action({
            "url": "https://www.example.com/post",
            "username": "yolo",
            "password": "fomo",
            "headers": [
                {"name": "X-Yolo",
                 "value": "Fomo"},
            ]
        })
        self.assertEqual(action_backend.url, "https://www.example.com/post")
        self.assertEqual(action_backend.headers, [{'name': 'X-Yolo', 'value': 'Fomo'}])
        self.assertEqual(action_backend.session.auth, ('yolo', 'fomo'))
        self.assertEqual(
            action_backend.session.headers,
            {'User-Agent': 'Zentral/unknown',
             'Accept-Encoding': 'gzip, deflate',
             'Accept': '*/*',
             'Connection': 'keep-alive',
             'Content-Type': 'application/json',
             'X-Yolo': 'Fomo'}
        )

    @patch("zentral.core.probes.action_backends.http.requests.Session.post")
    def test_trigger(self, session_post):
        probe = Mock()
        response = Mock()
        session_post.return_value = response
        action_backend = self._create_action({"url": "https://www.example.com/post"})
        event = BaseEvent(EventMetadata(), {"yolo": "fomo"})
        action_backend.trigger(event, probe)
        session_post.assert_called_once_with(
            "https://www.example.com/post",
            json=event.serialize(),
        )
        response.raise_for_status.assert_called_once()
