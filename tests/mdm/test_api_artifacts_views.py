from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import APIToken, User
from zentral.contrib.mdm.models import Artifact
from zentral.core.events.base import AuditEvent
from .utils import force_artifact, force_blueprint_artifact


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MDMArtifactsAPIViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.user.groups.set([cls.group])
        cls.api_key = APIToken.objects.update_or_create_for_user(cls.service_account)

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

    def login(self, *permissions):
        self.set_permissions(*permissions)
        self.client.force_login(self.user)

    def login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

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

    # list artifacts

    def test_list_artifacts_unauthorized(self):
        response = self.get(reverse("mdm_api:artifacts"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_artifacts_permission_denied(self):
        response = self.get(reverse("mdm_api:artifacts"))
        self.assertEqual(response.status_code, 403)

    def test_list_artifacts(self):
        artifact, _ = force_artifact()
        self.set_permissions("mdm.view_artifact")
        response = self.get(reverse("mdm_api:artifacts"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'id': str(artifact.pk),
              'name': artifact.name,
              'type': 'Profile',
              'channel': 'Device',
              'platforms': ['macOS'],
              'install_during_setup_assistant': False,
              'auto_update': True,
              'reinstall_interval': 0,
              'reinstall_on_os_update': 'No',
              'requires': [],
              'created_at': artifact.created_at.isoformat(),
              'updated_at': artifact.updated_at.isoformat()}]
        )

    def test_list_artifacts_name_filter(self):
        force_artifact()
        artifact, _ = force_artifact()
        self.set_permissions("mdm.view_artifact")
        response = self.get(reverse("mdm_api:artifacts"), data={"name": artifact.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'id': str(artifact.pk),
              'name': artifact.name,
              'type': 'Profile',
              'channel': 'Device',
              'platforms': ['macOS'],
              'install_during_setup_assistant': False,
              'auto_update': True,
              'reinstall_interval': 0,
              'reinstall_on_os_update': 'No',
              'requires': [],
              'created_at': artifact.created_at.isoformat(),
              'updated_at': artifact.updated_at.isoformat()}]
        )

    # get artifact

    def test_get_artifact_unauthorized(self):
        artifact, _ = force_artifact()
        response = self.get(reverse("mdm_api:artifact", args=(artifact.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_artifact_permission_denied(self):
        artifact, _ = force_artifact()
        response = self.get(reverse("mdm_api:artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_artifact(self):
        force_artifact()
        artifact, _ = force_artifact()
        self.set_permissions("mdm.view_artifact")
        response = self.get(reverse("mdm_api:artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'id': str(artifact.pk),
             'name': artifact.name,
             'type': 'Profile',
             'channel': 'Device',
             'platforms': ['macOS'],
             'install_during_setup_assistant': False,
             'auto_update': True,
             'reinstall_interval': 0,
             'reinstall_on_os_update': 'No',
             'requires': [],
             'created_at': artifact.created_at.isoformat(),
             'updated_at': artifact.updated_at.isoformat()}
        )

    # create artifact

    def test_create_artifact_unauthorized(self):
        response = self.post(reverse("mdm_api:artifacts"),
                             {"name": get_random_string(12)},
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_artifact_permission_denied(self):
        response = self.post(reverse("mdm_api:artifacts"),
                             {"name": get_random_string(12)})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_artifact(self, post_event):
        self.set_permissions("mdm.add_artifact")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:artifacts"),
                                 {"name": name,
                                  "type": "Profile",
                                  "channel": "Device"})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        artifact = Artifact.objects.get(name=name)
        self.assertEqual(
            response.json(),
            {'id': str(artifact.pk),
             'name': artifact.name,
             'type': 'Profile',
             'channel': 'Device',
             'platforms': ['iOS', 'iPadOS', 'macOS', 'tvOS'],
             'install_during_setup_assistant': False,
             'auto_update': True,
             'reinstall_interval': 0,
             'reinstall_on_os_update': 'No',
             'requires': [],
             'created_at': artifact.created_at.isoformat(),
             'updated_at': artifact.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "mdm.artifact",
                 "pk": str(artifact.pk),
                 "new_value": {
                     "pk": str(artifact.pk),
                     "name": name,
                     "type": 'Profile',
                     "channel": 'Device',
                     "platforms": ['iOS', 'iPadOS', 'macOS', 'tvOS'],
                     "install_during_setup_assistant": False,
                     "auto_update": True,
                     "reinstall_interval": 0,
                     "reinstall_on_os_update": 'No',
                     "requires": [],
                     "created_at": artifact.created_at,
                     "updated_at": artifact.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_artifact": [str(artifact.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # update artifact

    def test_update_artifact_unauthorized(self):
        artifact, _ = force_artifact()
        response = self.put(reverse("mdm_api:artifact", args=(artifact.pk,)),
                            {"name": get_random_string(12),
                             "type": "Profile",
                             "channel": "Device"},
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_artifact_permission_denied(self):
        artifact, _ = force_artifact()
        response = self.put(reverse("mdm_api:artifact", args=(artifact.pk,)),
                            {"name": get_random_string(12),
                             "type": "Profile",
                             "channel": "Device"})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_artifact(self, post_event):
        required_artifact, _ = force_artifact()
        blueprint_artifact, artifact, _ = force_blueprint_artifact(artifact_type=Artifact.Type.STORE_APP)
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["requires"], [])
        prev_value = artifact.serialize_for_event()
        self.set_permissions("mdm.change_artifact")
        new_name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(reverse("mdm_api:artifact", args=(artifact.pk,)),
                                {"name": new_name,
                                 "type": "Store App",
                                 "channel": "User",
                                 "platforms": ["iOS"],
                                 "requires": [str(required_artifact.pk)],
                                 "install_during_setup_assistant": True,
                                 "auto_update": False,
                                 "reinstall_interval": 1,
                                 "reinstall_on_os_update": "Patch",
                                 })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        artifact.refresh_from_db()
        self.assertEqual(artifact.name, new_name)
        self.assertEqual(artifact.type, "Store App")
        self.assertEqual(artifact.channel, "User")
        self.assertEqual(artifact.platforms, ["iOS"])
        self.assertEqual(list(artifact.requires.all()), [required_artifact])
        self.assertTrue(artifact.install_during_setup_assistant)
        self.assertFalse(artifact.auto_update)
        self.assertEqual(artifact.reinstall_interval, 1)
        self.assertEqual(artifact.reinstall_on_os_update, "Patch")
        self.assertEqual(
            response.json(),
            {"id": str(artifact.pk),
             "name": new_name,
             "type": "Store App",
             "channel": "User",
             "platforms": ["iOS"],
             "requires": [str(required_artifact.pk)],
             "install_during_setup_assistant": True,
             "auto_update": False,
             "reinstall_interval": 1,
             "reinstall_on_os_update": "Patch",
             'created_at': artifact.created_at.isoformat(),
             'updated_at': artifact.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "mdm.artifact",
                 "pk": str(artifact.pk),
                 "new_value": {
                     "pk": str(artifact.pk),
                     "name": new_name,
                     "type": 'Store App',
                     "channel": 'User',
                     "platforms": ['iOS'],
                     "install_during_setup_assistant": True,
                     "auto_update": False,
                     "reinstall_interval": 1,
                     "reinstall_on_os_update": 'Patch',
                     "requires": [{"pk": str(required_artifact.pk), "name": required_artifact.name}],
                     "created_at": artifact.created_at,
                     "updated_at": artifact.updated_at
                 },
                 "prev_value": prev_value
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_artifact": [str(artifact.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        blueprint.refresh_from_db()
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["requires"], [str(required_artifact.pk)])

    # delete artifact

    def test_delete_artifact_unauthorized(self):
        artifact, _ = force_artifact()
        response = self.delete(reverse("mdm_api:artifact", args=(artifact.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_artifact_permission_denied(self):
        artifact, _ = force_artifact()
        response = self.delete(reverse("mdm_api:artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_artifact_cannot_be_deleted(self):
        _, artifact, _ = force_blueprint_artifact()
        self.assertFalse(artifact.can_be_deleted())
        self.set_permissions("mdm.delete_artifact")
        response = self.delete(reverse("mdm_api:artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ['This artifact cannot be deleted'])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_artifact(self, post_event):
        artifact, _ = force_artifact()
        prev_value = artifact.serialize_for_event()
        self.set_permissions("mdm.delete_artifact")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(Artifact.objects.filter(name=artifact.name).count(), 0)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.artifact",
                 "pk": str(artifact.pk),
                 "prev_value": prev_value
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_artifact": [str(artifact.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
