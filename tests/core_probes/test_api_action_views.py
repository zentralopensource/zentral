from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from accounts.models import APIToken, User
from zentral.core.events.base import AuditEvent
from zentral.core.probes.models import Action, ActionBackend, ProbeSource
from .utils import force_action


class ProbeActionAPIViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        _, cls.api_key = APIToken.objects.update_or_create_for_user(cls.service_account)

    # utility methods

    def set_permissions(self, *permissions):
        if permissions:
            permission_filter = reduce(operator.or_, (
                Q(content_type__app_label=app_label, codename=codename)
                for app_label, codename in (
                    permission.split(".")
                    for permission in permissions
                )
            ))
            self.group.permissions.set(list(Permission.objects.filter(permission_filter)))
        else:
            self.group.permissions.clear()

    def _make_request(self, method, url, data=None, include_token=True):
        kwargs = {}
        if data is not None:
            kwargs["content_type"] = "application/json"
            kwargs["data"] = data
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return method(url, **kwargs)

    def delete(self, *args, **kwargs):
        return self._make_request(self.client.delete, *args, **kwargs)

    def get(self, *args, **kwargs):
        return self._make_request(self.client.get, *args, **kwargs)

    def post(self, *args, **kwargs):
        return self._make_request(self.client.post, *args, **kwargs)

    def put(self, *args, **kwargs):
        return self._make_request(self.client.put, *args, **kwargs)

    # list actions

    def test_list_actions_unauthorized(self):
        response = self.get(reverse("probes_api:actions"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_actions_permission_denied(self):
        response = self.get(reverse("probes_api:actions"))
        self.assertEqual(response.status_code, 403)

    def test_list_actions(self):
        force_action()
        action = force_action()
        self.set_permissions("probes.view_action")
        response = self.get(reverse("probes_api:actions") + f"?name={action.name}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            data,
            [{'id': str(action.pk),
              'name': action.name,
              'description': action.description,
              'backend': 'HTTP_POST',
              'http_post_kwargs': {"url": "https://www.example.com/post"},
              'slack_incoming_webhook_kwargs': None,
              'created_at': action.created_at.isoformat(),
              'updated_at': action.updated_at.isoformat()}]
        )

    # create action

    def test_create_action_unauthorized(self):
        response = self.post(reverse("probes_api:actions"), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_action_permission_denied(self):
        response = self.post(reverse("probes_api:actions"), {})
        self.assertEqual(response.status_code, 403)

    def test_create_action_missing_fields(self):
        self.set_permissions("probes.add_action")
        response = self.post(reverse("probes_api:actions"), {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'backend': ['This field is required.'], 'name': ['This field is required.']}
        )

    def test_create_action_unknown_backend(self):
        self.set_permissions("probes.add_action")
        response = self.post(
            reverse("probes_api:actions"),
            {"name": get_random_string(12),
             "backend": "YOLO"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'backend': ['"YOLO" is not a valid choice.']}
        )

    def test_create_http_post_action_missing_field(self):
        self.set_permissions("probes.add_action")
        response = self.post(
            reverse("probes_api:actions"),
            {"name": get_random_string(12),
             "backend": "HTTP_POST"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'http_post_kwargs': ['this field is required.']},
        )

    def test_create_http_post_action_missing_kwargs_field(self):
        self.set_permissions("probes.add_action")
        response = self.post(
            reverse("probes_api:actions"),
            {"name": get_random_string(12),
             "backend": "HTTP_POST",
             "http_post_kwargs": {}}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'http_post_kwargs': {'url': ['This field is required.']}},
        )

    def test_create_slack_incoming_webhook_action_missing_field(self):
        self.set_permissions("probes.add_action")
        response = self.post(
            reverse("probes_api:actions"),
            {"name": get_random_string(12),
             "backend": "SLACK_INCOMING_WEBHOOK"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'slack_incoming_webhook_kwargs': ['this field is required.']},
        )

    def test_create_slack_incoming_webhook_action_missing_kwargs_field(self):
        self.set_permissions("probes.add_action")
        response = self.post(
            reverse("probes_api:actions"),
            {"name": get_random_string(12),
             "backend": "SLACK_INCOMING_WEBHOOK",
             "slack_incoming_webhook_kwargs": {}}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'slack_incoming_webhook_kwargs': {'url': ['This field is required.']}},
        )

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_http_post_nones(self, post_event, send_notification):
        self.set_permissions("probes.add_action")
        name = get_random_string(12)
        description = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("probes_api:actions"),
                {"name": name,
                 "description": description,
                 "backend": "HTTP_POST",
                 "http_post_kwargs": {
                     "url": "https://www.example.com/post",
                     "username": None,
                     "password": None,
                     "headers": [],
                 },
                 "slack_incoming_webhook_kwargs": None}
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        action = Action.objects.get(name=name)
        self.assertEqual(response.json(), {
            'id': str(action.pk),
            'name': name,
            'description': description,
            'backend': 'HTTP_POST',
            'http_post_kwargs': {'url': 'https://www.example.com/post'},
            'slack_incoming_webhook_kwargs': None,
            'created_at': action.created_at.isoformat(),
            'updated_at': action.updated_at.isoformat(),
        })
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                  "model": "probes.action",
                  "pk": str(action.pk),
                  "new_value": {
                    "pk": str(action.pk),
                    "name": name,
                    "description": description,
                    "backend": "HTTP_POST",
                    "backend_kwargs": {"url": "https://www.example.com/post"},
                    "created_at": action.created_at,
                    "updated_at": action.updated_at,
                  }
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"probes_action": [str(action.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["probes", "zentral"])
        send_notification.assert_called_once_with("probes.change")

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_http_post_action_min(self, post_event, send_notification):
        self.set_permissions("probes.add_action")
        name = get_random_string(12)
        description = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("probes_api:actions"),
                {"name": name,
                 "description": description,
                 "backend": "HTTP_POST",
                 "http_post_kwargs": {"url": "https://www.example.com/post"}},
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        action = Action.objects.get(name=name)
        self.assertEqual(response.json(), {
            'id': str(action.pk),
            'name': name,
            'description': description,
            'backend': 'HTTP_POST',
            'http_post_kwargs': {'url': 'https://www.example.com/post'},
            'slack_incoming_webhook_kwargs': None,
            'created_at': action.created_at.isoformat(),
            'updated_at': action.updated_at.isoformat(),
        })
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                  "model": "probes.action",
                  "pk": str(action.pk),
                  "new_value": {
                    "pk": str(action.pk),
                    "name": name,
                    "description": description,
                    "backend": "HTTP_POST",
                    "backend_kwargs": {"url": "https://www.example.com/post"},
                    "created_at": action.created_at,
                    "updated_at": action.updated_at,
                  }
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"probes_action": [str(action.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["probes", "zentral"])
        send_notification.assert_called_once_with("probes.change")

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_http_post_action_max(self, post_event, send_notification):
        self.set_permissions("probes.add_action")
        name = get_random_string(12)
        description = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("probes_api:actions"),
                {"name": name,
                 "description": description,
                 "backend": "HTTP_POST",
                 "http_post_kwargs": {
                     "url": "https://www.example.com/post",
                     "username": "yolo",
                     "password": "fomo",
                     "headers": [
                         {"name": "Authorization",
                          "value": "Bearer yolofomo"},
                     ],
                 }},
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        action = Action.objects.get(name=name)
        self.assertEqual(response.json(), {
            'id': str(action.pk),
            'name': name,
            'description': description,
            'backend': 'HTTP_POST',
            'http_post_kwargs': {
                 "url": "https://www.example.com/post",
                 "username": "yolo",
                 "password": "fomo",
                 "headers": [
                     {"name": "Authorization",
                      "value": "Bearer yolofomo"},
                 ],
            },
            'slack_incoming_webhook_kwargs': None,
            'created_at': action.created_at.isoformat(),
            'updated_at': action.updated_at.isoformat(),
        })
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                  "model": "probes.action",
                  "pk": str(action.pk),
                  "new_value": {
                    "pk": str(action.pk),
                    "name": name,
                    "description": description,
                    "backend": "HTTP_POST",
                    "backend_kwargs": {
                        "url": "https://www.example.com/post",
                        "username": "yolo",
                        "password_hash": "48ffcddb8b19a5f98d4b1b8c08b4024b12b6f24affeb50b1265aed528a2dd671",
                        "headers": [
                            {"name": "Authorization",
                             "value_hash": "8f6c811daa3b5698210b6cfd2d015061375a4b7c1cfc97eb6a44da34bdd4843f"},
                        ],
                    },
                    "created_at": action.created_at,
                    "updated_at": action.updated_at,
                  }
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"probes_action": [str(action.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["probes", "zentral"])
        send_notification.assert_called_once_with("probes.change")

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_slack_incoming_webhook_action(self, post_event, send_notification):
        self.set_permissions("probes.add_action")
        name = get_random_string(12)
        description = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("probes_api:actions"),
                {"name": name,
                 "description": description,
                 "backend": "SLACK_INCOMING_WEBHOOK",
                 "slack_incoming_webhook_kwargs": {"url": "https://www.example.com/post"}},
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        action = Action.objects.get(name=name)
        self.assertEqual(response.json(), {
            'id': str(action.pk),
            'name': name,
            'description': description,
            'backend': 'SLACK_INCOMING_WEBHOOK',
            'http_post_kwargs': None,
            'slack_incoming_webhook_kwargs': {'url': 'https://www.example.com/post'},
            'created_at': action.created_at.isoformat(),
            'updated_at': action.updated_at.isoformat(),
        })
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                  "model": "probes.action",
                  "pk": str(action.pk),
                  "new_value": {
                    "pk": str(action.pk),
                    "name": name,
                    "description": description,
                    "backend": "SLACK_INCOMING_WEBHOOK",
                    "backend_kwargs": {
                        "url_hash": "265638c97b0030017b88a5fd7b3fb23b50f592edec664337d617863a2c2bd297"
                    },
                    "created_at": action.created_at,
                    "updated_at": action.updated_at,
                  }
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"probes_action": [str(action.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["probes", "zentral"])
        send_notification.assert_called_once_with("probes.change")

    # get action

    def test_get_action_unauthorized(self):
        action = force_action()
        response = self.get(reverse("probes_api:action", args=(action.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_action_permission_denied(self):
        action = force_action()
        response = self.get(reverse("probes_api:action", args=(action.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_action(self):
        action = force_action(backend=ActionBackend.SLACK_INCOMING_WEBHOOK)
        response = self.get(reverse("probes_api:action", args=(action.pk,)))
        self.set_permissions("probes.view_action")
        response = self.get(reverse("probes_api:action", args=(action.pk,)))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            data,
            {'id': str(action.pk),
             'name': action.name,
             'description': action.description,
             'backend': 'SLACK_INCOMING_WEBHOOK',
             'http_post_kwargs': None,
             'slack_incoming_webhook_kwargs': {"url": "https://www.example.com/post"},
             'created_at': action.created_at.isoformat(),
             'updated_at': action.updated_at.isoformat()}
        )

    # update action

    def test_update_action_unauthorized(self):
        action = force_action()
        response = self.put(reverse("probes_api:action", args=(action.pk,)), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_action_permission_denied(self):
        action = force_action()
        self.set_permissions("probes.view_action")
        response = self.put(reverse("probes_api:action", args=(action.pk,)), {})
        self.assertEqual(response.status_code, 403)

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_action(self, post_event, send_notification):
        action = force_action()
        prev_value = action.serialize_for_event()
        name = get_random_string(12)
        description = get_random_string(12)
        self.set_permissions("probes.change_action")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(
                reverse("probes_api:action", args=(action.pk,)),
                {"name": name,
                 "description": description,
                 "backend": "SLACK_INCOMING_WEBHOOK",
                 "slack_incoming_webhook_kwargs": {"url": "https://www.example.com/post"}},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        action2 = Action.objects.get(name=name)
        self.assertEqual(action, action2)
        self.assertEqual(response.json(), {
            'id': str(action.pk),
            'name': name,
            'description': description,
            'backend': 'SLACK_INCOMING_WEBHOOK',
            'http_post_kwargs': None,
            'slack_incoming_webhook_kwargs': {'url': 'https://www.example.com/post'},
            'created_at': action2.created_at.isoformat(),
            'updated_at': action2.updated_at.isoformat(),
        })
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                  "model": "probes.action",
                  "pk": str(action.pk),
                  "prev_value": prev_value,
                  "new_value": {
                    "pk": str(action.pk),
                    "name": name,
                    "description": description,
                    "backend": "SLACK_INCOMING_WEBHOOK",
                    "backend_kwargs": {
                        "url_hash": "265638c97b0030017b88a5fd7b3fb23b50f592edec664337d617863a2c2bd297"
                    },
                    "created_at": action2.created_at,
                    "updated_at": action2.updated_at,
                  }
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"probes_action": [str(action.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["probes", "zentral"])
        send_notification.assert_called_once_with("probes.change")

    # delete action

    def test_delete_action_unauthorized(self):
        action = force_action()
        response = self.delete(reverse("probes_api:action", args=(action.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_action_permission_denied(self):
        action = force_action()
        self.set_permissions("probes.view_action")
        response = self.delete(reverse("probes_api:action", args=(action.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_action_cannot_be_deleted(self):
        action = force_action()
        probe_source = ProbeSource.objects.create(name=get_random_string(12), body={})
        probe_source.actions.add(action)
        self.set_permissions("probes.delete_action")
        response = self.delete(reverse("probes_api:action", args=(action.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            ['This action cannot be deleted'],
        )

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_action(self, post_event, send_notification):
        action = force_action()
        prev_value = action.serialize_for_event()
        self.set_permissions("probes.delete_action")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("probes_api:action", args=(action.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        self.assertFalse(Action.objects.filter(name=action.name).exists())
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                  "model": "probes.action",
                  "pk": str(action.pk),
                  "prev_value": prev_value,
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"probes_action": [str(action.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["probes", "zentral"])
        send_notification.assert_called_once_with("probes.change")
