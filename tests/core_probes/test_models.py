import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.core.probes.models import Action, ActionBackend


class TestProbesModels(TestCase):
    def test_http_post_backend_no_pk(self):
        action = Action(backend=ActionBackend.HTTP_POST)
        action.pk = None  # force the error
        with self.assertRaises(ValueError) as cm:
            action.set_backend_kwargs({"password": "yolo"})
        self.assertEqual(cm.exception.args[0], "Backend instance must have a primary key")

    def test_http_post_backend_kwargs(self):
        name = get_random_string(12)
        description = get_random_string(12)
        action = Action(
            id=uuid.uuid4(),
            name=name,
            description=description,
            backend=ActionBackend.HTTP_POST,
        )
        backend_kwargs = {
            "username": "yolo",
            "password": "fomo",
            "headers": [
                {"name": "X-Custom-Auth",
                 "value": "haha"},
                {"name": "X-Custom-Auth-2",
                 "value": "haha2"},
            ]
        }
        action.set_backend_kwargs(backend_kwargs)
        action.save()
        # encrypted
        self.assertEqual(
            action.backend_kwargs,
            {'headers': [{'name': 'X-Custom-Auth', 'value': 'noop$aGFoYQ=='},
                         {'name': 'X-Custom-Auth-2', 'value': 'noop$aGFoYTI='}],
             'password': 'noop$Zm9tbw==',
             'username': 'yolo'}
        )
        # decrypted
        self.assertEqual(action.get_backend_kwargs(), backend_kwargs)
        # rewraped → noop
        action.rewrap_secrets()
        self.assertEqual(
            action.backend_kwargs,
            {'headers': [{'name': 'X-Custom-Auth', 'value': 'noop$aGFoYQ=='},
                         {'name': 'X-Custom-Auth-2', 'value': 'noop$aGFoYTI='}],
             'password': 'noop$Zm9tbw==',
             'username': 'yolo'}
        )
        # for events
        self.assertEqual(
            action.serialize_for_event(),
            {'backend': 'HTTP_POST',
             'backend_kwargs': {
                 'headers': [{'name': 'X-Custom-Auth',
                              'value_hash': '090b235e9eb8f197f2dd927937222c570396d971222d9009a9189e2b6cc0a2c1'},
                             {'name': 'X-Custom-Auth-2',
                              'value_hash': '6affeef941b875cbaea50d0dbdbee82d7c6b5d5dca215ba136174528d2b1e4ed'}],
                 'password_hash': '48ffcddb8b19a5f98d4b1b8c08b4024b12b6f24affeb50b1265aed528a2dd671',
                 'username': 'yolo'
             },
             'created_at': action.created_at,
             'description': description,
             'name': name,
             'pk': str(action.pk),
             'updated_at': action.updated_at}
        )
        # backend specific methods
        self.assertEqual(action.get_http_post_kwargs(), backend_kwargs)
        self.assertIsNone(action.get_slack_incoming_webhook_kwargs())

    def test_slack_incoming_webhook_backend_kwargs(self):
        name = get_random_string(12)
        description = get_random_string(12)
        action = Action(
            id=uuid.uuid4(),
            name=name,
            description=description,
            backend=ActionBackend.SLACK_INCOMING_WEBHOOK,
        )
        backend_kwargs = {"url": "https://example.slack.com/yolo"}
        action.set_backend_kwargs(backend_kwargs)
        action.save()
        # encrypted
        self.assertEqual(
            action.backend_kwargs,
            {"url": "noop$aHR0cHM6Ly9leGFtcGxlLnNsYWNrLmNvbS95b2xv"},
        )
        # decrypted
        self.assertEqual(action.get_backend_kwargs(), backend_kwargs)
        # rewraped → noop
        action.rewrap_secrets()
        self.assertEqual(
            action.backend_kwargs,
            {"url": "noop$aHR0cHM6Ly9leGFtcGxlLnNsYWNrLmNvbS95b2xv"},
        )
        # for events
        self.assertEqual(
            action.serialize_for_event(),
            {'backend': 'SLACK_INCOMING_WEBHOOK',
             'backend_kwargs': {
                 'url_hash': "3e2fe3b6026888d07d94e5b3a56372e10414792b1bc234482e4e8b798023799a"
             },
             'created_at': action.created_at,
             'description': description,
             'name': name,
             'pk': str(action.pk),
             'updated_at': action.updated_at}
        )
        # backend specific methods
        self.assertIsNone(action.get_http_post_kwargs())
        self.assertEqual(action.get_slack_incoming_webhook_kwargs(), backend_kwargs)
