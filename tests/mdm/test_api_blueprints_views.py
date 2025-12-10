from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from accounts.models import APIToken, User
from zentral.contrib.mdm.models import Blueprint
from zentral.core.events.base import AuditEvent
from .utils import (force_blueprint, force_blueprint_artifact,
                    force_filevault_config, force_location,
                    force_recovery_password_config,
                    force_software_update_enforcement)


class MDMBlueprintsAPIViewsTestCase(TestCase):
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

    # list blueprints

    def test_list_blueprints_unauthorized(self):
        response = self.get(reverse("mdm_api:blueprints"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_blueprints_permission_denied(self):
        response = self.get(reverse("mdm_api:blueprints"))
        self.assertEqual(response.status_code, 403)

    def test_list_blueprints(self):
        self.set_permissions("mdm.view_blueprint")
        blueprint = force_blueprint()
        response = self.get(reverse("mdm_api:blueprints"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'id': blueprint.pk,
              'name': blueprint.name,
              'inventory_interval': 86400,
              'collect_apps': 0,
              'collect_certificates': 0,
              'collect_profiles': 0,
              'default_location': None,
              'filevault_config': None,
              'legacy_profiles_via_ddm': True,
              'recovery_password_config': None,
              'software_update_enforcements': [],
              'created_at': blueprint.created_at.isoformat(),
              'updated_at': blueprint.updated_at.isoformat()}]
        )

    def test_list_blueprints_name_filter(self):
        force_blueprint()
        filevault_config = force_filevault_config()
        recovery_password_config = force_recovery_password_config()
        sue = force_software_update_enforcement()
        blueprint = force_blueprint(filevault_config=filevault_config,
                                    recovery_password_config=recovery_password_config,
                                    software_update_enforcement=sue)
        self.set_permissions("mdm.view_blueprint")
        response = self.get(reverse("mdm_api:blueprints"), data={"name": blueprint.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'id': blueprint.pk,
              'name': blueprint.name,
              'inventory_interval': 86400,
              'collect_apps': 0,
              'collect_certificates': 0,
              'collect_profiles': 0,
              'default_location': None,
              'filevault_config': filevault_config.pk,
              'legacy_profiles_via_ddm': True,
              'recovery_password_config': recovery_password_config.pk,
              'software_update_enforcements': [sue.pk],
              'created_at': blueprint.created_at.isoformat(),
              'updated_at': blueprint.updated_at.isoformat()}]
        )

    # get blueprint

    def test_get_blueprint_unauthorized(self):
        blueprint = force_blueprint()
        response = self.get(reverse("mdm_api:blueprint", args=(blueprint.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_blueprint_permission_denied(self):
        blueprint = force_blueprint()
        response = self.get(reverse("mdm_api:blueprint", args=(blueprint.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_blueprint(self):
        force_blueprint()
        blueprint = force_blueprint()
        self.set_permissions("mdm.view_blueprint")
        response = self.get(reverse("mdm_api:blueprint", args=(blueprint.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'id': blueprint.pk,
             'name': blueprint.name,
             'inventory_interval': 86400,
             'collect_apps': 0,
             'collect_certificates': 0,
             'collect_profiles': 0,
             'default_location': None,
             'filevault_config': None,
             'legacy_profiles_via_ddm': True,
             'recovery_password_config': None,
             'software_update_enforcements': [],
             'created_at': blueprint.created_at.isoformat(),
             'updated_at': blueprint.updated_at.isoformat()}
        )

    # create blueprint

    def test_create_blueprint_unauthorized(self):
        response = self.post(reverse("mdm_api:blueprints"),
                             {"name": get_random_string(12)},
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_blueprint_permission_denied(self):
        response = self.post(reverse("mdm_api:blueprints"),
                             {"name": get_random_string(12)})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_blueprint(self, post_event):
        self.set_permissions("mdm.add_blueprint")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:blueprints"),
                                 {"name": name})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        blueprint = Blueprint.objects.get(name=name)
        self.assertEqual(
            response.json(),
            {'id': blueprint.pk,
             'name': blueprint.name,
             'inventory_interval': 86400,
             'collect_apps': 0,
             'collect_certificates': 0,
             'collect_profiles': 0,
             'default_location': None,
             'filevault_config': None,
             'legacy_profiles_via_ddm': True,
             'recovery_password_config': None,
             'software_update_enforcements': [],
             'created_at': blueprint.created_at.isoformat(),
             'updated_at': blueprint.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "mdm.blueprint",
                 "pk": str(blueprint.pk),
                 "new_value": {
                     "pk": blueprint.pk,
                     "name": name,
                     "inventory_interval": 86400,
                     "collect_apps": 'NO',
                     "collect_certificates": 'NO',
                     "collect_profiles": 'NO',
                     "legacy_profiles_via_ddm": True,
                     "created_at": blueprint.created_at,
                     "updated_at": blueprint.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_blueprint": [str(blueprint.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # update blueprint

    def test_update_blueprint_unauthorized(self):
        blueprint = force_blueprint()
        response = self.put(reverse("mdm_api:blueprint", args=(blueprint.pk,)),
                            {"name": get_random_string(12)},
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_blueprint_permission_denied(self):
        blueprint = force_blueprint()
        response = self.put(reverse("mdm_api:blueprint", args=(blueprint.pk,)),
                            {"name": get_random_string(12)})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_blueprint(self, post_event):
        blueprint = force_blueprint()
        filevault_config = force_filevault_config()
        sue = force_software_update_enforcement()
        recovery_password_config = force_recovery_password_config()
        prev_value = blueprint.serialize_for_event()
        self.set_permissions("mdm.change_blueprint")
        new_name = get_random_string(12)
        location = force_location()
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(reverse("mdm_api:blueprint", args=(blueprint.pk,)),
                                {"name": new_name,
                                 "inventory_interval": 86401,
                                 "collect_apps": 1,
                                 "collect_certificates": 2,
                                 "collect_profiles": 2,
                                 "default_location": location.pk,
                                 "filevault_config": filevault_config.pk,
                                 "legacy_profiles_via_ddm": False,
                                 "recovery_password_config": recovery_password_config.pk,
                                 "software_update_enforcements": [sue.pk]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        blueprint.refresh_from_db()
        self.assertEqual(blueprint.name, new_name)
        self.assertEqual(blueprint.inventory_interval, 86401)
        self.assertEqual(blueprint.collect_apps, 1)
        self.assertEqual(blueprint.collect_certificates, 2)
        self.assertEqual(blueprint.collect_profiles, 2)
        self.assertEqual(blueprint.default_location, location)
        self.assertEqual(blueprint.filevault_config, filevault_config)
        self.assertFalse(blueprint.legacy_profiles_via_ddm)
        self.assertEqual(blueprint.recovery_password_config, recovery_password_config)
        self.assertEqual(list(blueprint.software_update_enforcements.all()), [sue])
        self.assertEqual(
            response.json(),
            {'id': blueprint.pk,
             'name': blueprint.name,
             'inventory_interval': 86401,
             'collect_apps': 1,
             'collect_certificates': 2,
             'collect_profiles': 2,
             'default_location': location.pk,
             'filevault_config': filevault_config.pk,
             'legacy_profiles_via_ddm': False,
             'recovery_password_config': recovery_password_config.pk,
             'software_update_enforcements': [sue.pk,],
             'created_at': blueprint.created_at.isoformat(),
             'updated_at': blueprint.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "mdm.blueprint",
                 "pk": str(blueprint.pk),
                 "new_value": {
                     "pk": blueprint.pk,
                     "name": blueprint.name,
                     "inventory_interval": 86401,
                     "collect_apps": 'MANAGED_ONLY',
                     "collect_certificates": 'ALL',
                     "collect_profiles": 'ALL',
                     "default_location": {"pk": location.pk, "mdm_info_id": str(location.mdm_info_id)},
                     "filevault_config": {"name": filevault_config.name, "pk": filevault_config.pk},
                     "legacy_profiles_via_ddm": False,
                     "recovery_password_config": {"name": recovery_password_config.name,
                                                  "pk": recovery_password_config.pk},
                     "software_update_enforcements": [{"pk": sue.pk, "name": sue.name}],
                     "created_at": blueprint.created_at,
                     "updated_at": blueprint.updated_at
                 },
                 "prev_value": prev_value
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_blueprint": [str(blueprint.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # delete blueprint

    def test_delete_blueprint_unauthorized(self):
        blueprint = force_blueprint()
        response = self.delete(reverse("mdm_api:blueprint", args=(blueprint.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_blueprint_permission_denied(self):
        blueprint = force_blueprint()
        response = self.delete(reverse("mdm_api:blueprint", args=(blueprint.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_blueprint_cannot_be_deleted(self):
        blueprint = force_blueprint()
        force_blueprint_artifact(blueprint=blueprint)
        self.assertFalse(blueprint.can_be_deleted())
        self.set_permissions("mdm.delete_blueprint")
        response = self.delete(reverse("mdm_api:blueprint", args=(blueprint.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ['This blueprint cannot be deleted'])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_blueprint(self, post_event):
        blueprint = force_blueprint()
        prev_value = blueprint.serialize_for_event()
        self.set_permissions("mdm.delete_blueprint")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:blueprint", args=(blueprint.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(Blueprint.objects.filter(name=blueprint.name).count(), 0)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.blueprint",
                 "pk": str(blueprint.pk),
                 "prev_value": prev_value
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_blueprint": [str(blueprint.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
