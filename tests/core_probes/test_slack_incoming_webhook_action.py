from unittest.mock import patch, Mock
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.core.events.base import BaseEvent, EventMetadata
from zentral.core.probes.models import ActionBackend, ProbeSource
from .utils import force_action


class SlackIncomingWebhookActionTests(TestCase):
    def _create_action(self, kwargs):
        action = force_action(
            backend=ActionBackend.SLACK_INCOMING_WEBHOOK,
            backend_kwargs=kwargs
        )
        return action.get_backend(load=True)

    def test_default_config(self):
        action_backend = self._create_action({"url": "https://www.example.com/post"})
        self.assertEqual(action_backend.url, "https://www.example.com/post")
        self.assertIsNone(action_backend.session.auth)
        self.assertEqual(
            action_backend.session.headers,
            {'User-Agent': 'Zentral/unknown',
             'Accept-Encoding': 'gzip, deflate',
             'Accept': '*/*',
             'Connection': 'keep-alive',
             'Content-Type': 'application/json'},
        )

    @patch("zentral.core.probes.action_backends.http.requests.Session.post")
    def test_trigger(self, session_post):
        probe_name = get_random_string(12)
        probe_source = ProbeSource.objects.create(model="BaseProbe", name=probe_name, body={})
        probe = probe_source.load()
        response = Mock()
        session_post.return_value = response
        action_backend = self._create_action({"url": "https://www.example.com/post"})
        event = BaseEvent(EventMetadata(), {"yolo": "fomo"})
        action_backend.trigger(event, probe)
        session_post.assert_called_once()
        response.raise_for_status.assert_called_once()
