from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import APIToken, User
from zentral.contrib.inventory.models import Tag
from zentral.core.events.base import AuditEvent
from zentral.core.probes.models import ProbeSource
from .utils import force_action, force_probe_source


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class ProbeAPIViewsTestCase(TestCase):
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

    # list probes

    def test_list_probes_unauthorized(self):
        response = self.get(reverse("probes_api:probes"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_probes_permission_denied(self):
        self.set_permissions("probes.view_action")
        response = self.get(reverse("probes_api:probes"))
        self.assertEqual(response.status_code, 403)

    def test_list_probes(self):
        force_probe_source()
        probe_source = force_probe_source()
        self.set_permissions("probes.view_probesource")
        response = self.get(reverse("probes_api:probes") + f"?name={probe_source.name}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            data,
            [{'id': probe_source.pk,
              'name': probe_source.name,
              'slug': probe_source.slug,
              'description': '',
              'inventory_filters': [],
              'metadata_filters': [{'event_types': ['zentral_login']}],
              'payload_filters': [],
              'incident_severity': None,
              'active': True,
              'actions': [str(probe_source.actions.first().pk)],
              'created_at': probe_source.created_at.isoformat(),
              'updated_at': probe_source.updated_at.isoformat()}]
        )

    # create probe

    def test_create_probe_unauthorized(self):
        response = self.post(reverse("probes_api:probes"), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_probe_permission_denied(self):
        self.set_permissions("probes.view_probesource")
        response = self.post(reverse("probes_api:probes"), {})
        self.assertEqual(response.status_code, 403)

    def test_create_probe_missing_fields(self):
        self.set_permissions("probes.add_probesource")
        response = self.post(reverse("probes_api:probes"), {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'name': ['This field is required.']},
        )

    def test_create_probe_field_errors(self):
        probe = force_probe_source()
        self.set_permissions("probes.add_probesource")
        response = self.post(
            reverse("probes_api:probes"),
            {"incident_severity": 0,
             "name": probe.name,
             "active": "ACTIVE",
             "inventory_filters": [{"tag_ids": ["a"]}],
             "metadata_filters": {"un": 1},
             "payload_filters": [[{"attr": "yolo", "operator": "IN", "values": ["fomo"]}]]}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'active': ['Must be a valid boolean.'],
             'incident_severity': ['"0" is not a valid choice.'],  # A probe incident cannot be closed!
             'inventory_filters': {'0': {'tag_ids': {'0': ['A valid integer is '
                                                           'required.']}}},
             'metadata_filters': ['Expected a list of items but got type "dict".'],
             'name': ['probe source with this name already exists.'],
             'payload_filters': {'0': {'0': {'attribute': ['This field is required.']}}}}
        )

    def test_create_probe_slug_error(self):
        probe = force_probe_source()
        self.set_permissions("probes.add_probesource")
        response = self.post(
            reverse("probes_api:probes"),
            {"name": probe.name.upper()},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'name': ['this name produces a slug that is already taken by another probe source']},
        )

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_probe(self, post_event, send_notification):
        name = get_random_string(12)
        action = force_action()
        self.set_permissions("probes.add_probesource")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("probes_api:probes"),
                {"name": name,
                 "description": "fomo",
                 "active": True,
                 "metadata_filters": [{"event_types": ["zentral_login"]}],
                 "payload_filters": [[{"attribute": "yolo", "operator": "IN", "values": ["fomo"]}]],
                 "incident_severity": 300,
                 "actions": [str(action.pk)]},
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 2)  # Because of the view callback that is not used and the save() one.
        probe_source = ProbeSource.objects.get(name=name)
        self.assertEqual(
            response.json(),
            {"id": probe_source.pk,
             "name": name,
             "slug": probe_source.slug,
             "description": "fomo",
             "active": True,
             "inventory_filters": [],
             "metadata_filters": [{"event_types": ["zentral_login"]}],
             "payload_filters": [[{"attribute": "yolo", "operator": "IN", "values": ["fomo"]}]],
             "incident_severity": 300,
             "actions": [str(action.pk)],
             "created_at": probe_source.created_at.isoformat(),
             "updated_at": probe_source.updated_at.isoformat()}
        )
        self.assertEqual(list(probe_source.actions.all()), [action])
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {'action': 'created',
             'object': {'model': 'probes.probesource',
                        'new_value': {'actions': [{'name': action.name,
                                                   'pk': str(action.pk)}],
                                      'active': True,
                                      'created_at': probe_source.created_at,
                                      'description': 'fomo',
                                      'incident_severity': 300,
                                      'metadata_filters': [{'event_types': ['zentral_login']}],
                                      'name': probe_source.name,
                                      'payload_filters': [[{'attribute': 'yolo',
                                                            'operator': 'IN',
                                                            'values': ['fomo']}]],
                                      'pk': probe_source.pk,
                                      'slug': probe_source.slug,
                                      'updated_at': probe_source.updated_at},
                        'pk': str(probe_source.pk)}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"probes_probe_source": [str(probe_source.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["probes", "zentral"])
        send_notification.assert_called_once_with("probes.change")

    # get probe

    def test_get_probe_unauthorized(self):
        probe_source = force_probe_source()
        response = self.get(reverse("probes_api:probe", args=(probe_source.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_probe_permission_denied(self):
        probe_source = force_probe_source()
        response = self.get(reverse("probes_api:probe", args=(probe_source.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_probe(self):
        probe_source = force_probe_source()
        self.set_permissions("probes.view_probesource")
        response = self.get(reverse("probes_api:probe", args=(probe_source.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'actions': [str(probe_source.actions.first().pk)],
             'active': True,
             'created_at': probe_source.created_at.isoformat(),
             'description': '',
             'id': probe_source.pk,
             'incident_severity': None,
             'inventory_filters': [],
             'metadata_filters': [{'event_types': ['zentral_login']}],
             'name': probe_source.name,
             'payload_filters': [],
             'slug': probe_source.slug,
             'updated_at': probe_source.updated_at.isoformat()}
        )

    # update probe

    def test_update_probe_unauthorized(self):
        probe_source = force_probe_source()
        response = self.put(reverse("probes_api:probe", args=(probe_source.pk,)), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_probe_permission_denied(self):
        probe_source = force_probe_source()
        self.set_permissions("probes.view_probesource")
        response = self.put(reverse("probes_api:probe", args=(probe_source.pk,)), {})
        self.assertEqual(response.status_code, 403)

    def test_update_probe_slug_error(self):
        probe_source_1 = force_probe_source()
        probe_source_2 = force_probe_source()
        self.set_permissions("probes.change_probesource")
        response = self.put(
            reverse("probes_api:probe", args=(probe_source_2.pk,)),
            {"name": probe_source_1.name.upper()}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'name': ['this name produces a slug that is already taken by another probe source']},
        )

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_probe(self, post_event, send_notification):
        probe_source = force_probe_source()
        prev_value = probe_source.serialize_for_event()
        new_name = get_random_string(12)
        action = force_action()
        tag = Tag.objects.create(name=get_random_string(12))
        self.set_permissions("probes.change_probesource")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(
                reverse("probes_api:probe", args=(probe_source.pk,)),
                {"name": new_name,
                 "description": "fomo",
                 "active": False,
                 "incident_severity": None,
                 "inventory_filters": [{"tag_ids": [tag.pk], "types": ["DESKTOP"]}],
                 "metadata_filters": [{"event_types": ["zentral_login"]}],
                 "payload_filters": [[{"attribute": "yolo", "operator": "IN", "values": ["fomo"]}]],
                 "actions": [str(action.pk)]},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 2)  # Because of the view callback that is not used and the save() one.
        probe_source_2 = ProbeSource.objects.get(name=new_name)
        self.assertEqual(probe_source, probe_source_2)
        self.assertEqual(
            response.json(),
            {"id": probe_source.pk,
             "name": new_name,
             "slug": probe_source_2.slug,
             "description": "fomo",
             "active": False,
             "inventory_filters": [{"tag_ids": [tag.pk], "types": ["DESKTOP"]}],
             "metadata_filters": [{"event_types": ["zentral_login"]}],
             "payload_filters": [[{"attribute": "yolo", "operator": "IN", "values": ["fomo"]}]],
             "incident_severity": None,
             "actions": [str(action.pk)],
             "created_at": probe_source_2.created_at.isoformat(),
             "updated_at": probe_source_2.updated_at.isoformat()}
        )
        self.assertEqual(list(probe_source_2.actions.all()), [action])
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {'action': 'updated',
             'object': {'model': 'probes.probesource',
                        'prev_value': prev_value,
                        'new_value': {'actions': [{'name': action.name,
                                                   'pk': str(action.pk)}],
                                      'active': False,
                                      'created_at': probe_source_2.created_at,
                                      'description': 'fomo',
                                      'inventory_filters': [{'tag_ids': [tag.pk], 'types': ['DESKTOP']}],
                                      'metadata_filters': [{'event_types': ['zentral_login']}],
                                      'name': new_name,
                                      'payload_filters': [[{'attribute': 'yolo',
                                                            'operator': 'IN',
                                                            'values': ['fomo']}]],
                                      'pk': probe_source.pk,
                                      'slug': probe_source_2.slug,
                                      'updated_at': probe_source_2.updated_at},
                        'pk': str(probe_source.pk)}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"probes_probe_source": [str(probe_source.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["probes", "zentral"])
        send_notification.assert_called_once_with("probes.change")

    # delete probe

    def test_delete_probe_unauthorized(self):
        probe_source = force_probe_source()
        response = self.delete(reverse("probes_api:probe", args=(probe_source.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_probe_permission_denied(self):
        probe_source = force_probe_source()
        self.set_permissions("probes.view_probesource")
        response = self.delete(reverse("probes_api:probe", args=(probe_source.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_probe(self, post_event, send_notification):
        probe_source = force_probe_source()
        prev_value = probe_source.serialize_for_event()
        self.set_permissions("probes.delete_probesource")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("probes_api:probe", args=(probe_source.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 2)  # Because of the view callback that is not used and the save() one.
        self.assertFalse(ProbeSource.objects.filter(name=probe_source.name).exists())
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {'action': 'deleted',
             'object': {'model': 'probes.probesource',
                        'pk': str(probe_source.pk),
                        'prev_value': prev_value}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"probes_probe_source": [str(probe_source.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["probes", "zentral"])
        send_notification.assert_called_once_with("probes.change")
