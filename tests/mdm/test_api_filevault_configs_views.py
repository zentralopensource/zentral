from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import APIToken, User
from zentral.contrib.mdm.models import FileVaultConfig
from zentral.core.events.base import AuditEvent
from .utils import force_blueprint, force_filevault_config


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MDMFileVaultConfigsAPIViewsTestCase(TestCase):
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

    # list FileVault configs

    def test_list_filevault_configs_unauthorized(self):
        response = self.get(reverse("mdm_api:filevault_configs"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_filevault_configs_permission_denied(self):
        response = self.get(reverse("mdm_api:filevault_configs"))
        self.assertEqual(response.status_code, 403)

    def test_list_filevault_configs(self):
        fv_config = force_filevault_config()
        self.set_permissions("mdm.view_filevaultconfig")
        response = self.get(reverse("mdm_api:filevault_configs"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'id': fv_config.pk,
              'name': fv_config.name,
              'escrow_location_display_name': fv_config.escrow_location_display_name,
              'at_login_only': False,
              'bypass_attempts': -1,
              'show_recovery_key': False,
              'destroy_key_on_standby': False,
              'prk_rotation_interval_days': 0,
              'created_at': fv_config.created_at.isoformat(),
              'updated_at': fv_config.updated_at.isoformat()}]
        )

    def test_list_filevault_configs_name_filter(self):
        force_filevault_config()
        fv_config = force_filevault_config()
        self.set_permissions("mdm.view_filevaultconfig")
        response = self.get(reverse("mdm_api:filevault_configs"), data={"name": fv_config.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'id': fv_config.pk,
              'name': fv_config.name,
              'escrow_location_display_name': fv_config.escrow_location_display_name,
              'at_login_only': False,
              'bypass_attempts': -1,
              'show_recovery_key': False,
              'destroy_key_on_standby': False,
              'prk_rotation_interval_days': 0,
              'created_at': fv_config.created_at.isoformat(),
              'updated_at': fv_config.updated_at.isoformat()}]
        )

    # get FileVault config

    def test_get_filevault_config_unauthorized(self):
        fv_config = force_filevault_config()
        response = self.get(reverse("mdm_api:filevault_config", args=(fv_config.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_filevault_config_permission_denied(self):
        fv_config = force_filevault_config()
        response = self.get(reverse("mdm_api:blueprint", args=(fv_config.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_filevault_config(self):
        force_filevault_config()
        fv_config = force_filevault_config()
        self.set_permissions("mdm.view_filevaultconfig")
        response = self.get(reverse("mdm_api:filevault_config", args=(fv_config.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'id': fv_config.pk,
             'name': fv_config.name,
             'escrow_location_display_name': fv_config.escrow_location_display_name,
             'at_login_only': False,
             'bypass_attempts': -1,
             'show_recovery_key': False,
             'destroy_key_on_standby': False,
             'prk_rotation_interval_days': 0,
             'created_at': fv_config.created_at.isoformat(),
             'updated_at': fv_config.updated_at.isoformat()}
        )

    # create FileVault config

    def test_create_filevault_config_unauthorized(self):
        response = self.post(reverse("mdm_api:filevault_configs"),
                             {"name": get_random_string(12)},
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_filevault_config_permission_denied(self):
        response = self.post(reverse("mdm_api:filevault_configs"),
                             {"name": get_random_string(12)})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_filevault_config(self, post_event):
        self.set_permissions("mdm.add_filevaultconfig")
        name = get_random_string(12)
        escrow_name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:filevault_configs"),
                                 {"name": name,
                                  "escrow_location_display_name": escrow_name})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        fv_config = FileVaultConfig.objects.get(name=name)
        self.assertEqual(
            response.json(),
            {'id': fv_config.pk,
             'name': fv_config.name,
             'escrow_location_display_name': escrow_name,
             'at_login_only': False,
             'bypass_attempts': -1,
             'show_recovery_key': False,
             'destroy_key_on_standby': False,
             'prk_rotation_interval_days': 0,
             'created_at': fv_config.created_at.isoformat(),
             'updated_at': fv_config.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "mdm.filevaultconfig",
                 "pk": str(fv_config.pk),
                 "new_value": {
                     "pk": fv_config.pk,
                     "name": name,
                     "escrow_location_display_name": escrow_name,
                     "at_login_only": False,
                     "bypass_attempts": -1,
                     "show_recovery_key": False,
                     "destroy_key_on_standby": False,
                     "prk_rotation_interval_days": 0,
                     "created_at": fv_config.created_at,
                     "updated_at": fv_config.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_filevault_config": [str(fv_config.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # update FileVault config

    def test_update_filevault_config_unauthorized(self):
        fv_config = force_filevault_config()
        response = self.put(reverse("mdm_api:filevault_config", args=(fv_config.pk,)),
                            {"name": get_random_string(12),
                             "escrow_location_display_name": get_random_string(12)},
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_filevault_config_permission_denied(self):
        fv_config = force_filevault_config()
        response = self.put(reverse("mdm_api:filevault_config", args=(fv_config.pk,)),
                            {"name": get_random_string(12),
                             "escrow_location_display_name": get_random_string(12)})
        self.assertEqual(response.status_code, 403)

    def test_update_filevault_config_bypass_attempts_when_not_at_login_only_error(self):
        fv_config = force_filevault_config()
        self.set_permissions("mdm.change_filevaultconfig")
        response = self.put(reverse("mdm_api:filevault_config", args=(fv_config.pk,)),
                            {"name": get_random_string(12),
                             "escrow_location_display_name": get_random_string(12),
                             "at_login_only": False,
                             "bypass_attempts": 1})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'bypass_attempts': ['Must be -1 when at_login_only is False']})

    def test_update_filevault_config_bypass_attempts_when_at_login_only_error(self):
        fv_config = force_filevault_config()
        self.set_permissions("mdm.change_filevaultconfig")
        response = self.put(reverse("mdm_api:filevault_config", args=(fv_config.pk,)),
                            {"name": get_random_string(12),
                             "escrow_location_display_name": get_random_string(12),
                             "at_login_only": True,
                             "bypass_attempts": -1})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'bypass_attempts': ['Must be >= 0 when at_login_only is True']})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_filevault_config(self, post_event):
        fv_config = force_filevault_config()
        prev_value = fv_config.serialize_for_event()
        self.set_permissions("mdm.change_filevaultconfig")
        new_name = get_random_string(12)
        new_escrow_name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(reverse("mdm_api:filevault_config", args=(fv_config.pk,)),
                                {"name": new_name,
                                 "escrow_location_display_name": new_escrow_name,
                                 "at_login_only": True,
                                 "bypass_attempts": 1,
                                 "show_recovery_key": True,
                                 "destroy_key_on_standby": True,
                                 "prk_rotation_interval_days": 90})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        fv_config.refresh_from_db()
        self.assertEqual(fv_config.name, new_name)
        self.assertEqual(fv_config.escrow_location_display_name, new_escrow_name)
        self.assertTrue(fv_config.at_login_only)
        self.assertEqual(fv_config.bypass_attempts, 1)
        self.assertTrue(fv_config.show_recovery_key)
        self.assertTrue(fv_config.destroy_key_on_standby)
        self.assertEqual(fv_config.prk_rotation_interval_days, 90)
        self.assertEqual(
            response.json(),
            {'id': fv_config.pk,
             'name': new_name,
             'escrow_location_display_name': new_escrow_name,
             'at_login_only': True,
             'bypass_attempts': 1,
             'show_recovery_key': True,
             'destroy_key_on_standby': True,
             'prk_rotation_interval_days': 90,
             'created_at': fv_config.created_at.isoformat(),
             'updated_at': fv_config.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "mdm.filevaultconfig",
                 "pk": str(fv_config.pk),
                 "new_value": {
                     "pk": fv_config.pk,
                     "name": new_name,
                     "escrow_location_display_name": new_escrow_name,
                     "at_login_only": True,
                     "bypass_attempts": 1,
                     "show_recovery_key": True,
                     "destroy_key_on_standby": True,
                     "prk_rotation_interval_days": 90,
                     "created_at": fv_config.created_at,
                     "updated_at": fv_config.updated_at
                 },
                 "prev_value": prev_value
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_filevault_config": [str(fv_config.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # delete FileVault config

    def test_delete_filevault_config_unauthorized(self):
        fv_config = force_filevault_config()
        response = self.delete(reverse("mdm_api:filevault_config", args=(fv_config.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_filevault_config_permission_denied(self):
        fv_config = force_filevault_config()
        response = self.delete(reverse("mdm_api:filevault_config", args=(fv_config.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_filevault_config_cannot_be_deleted(self):
        fv_config = force_filevault_config()
        force_blueprint(filevault_config=fv_config)
        self.set_permissions("mdm.delete_filevaultconfig")
        response = self.delete(reverse("mdm_api:filevault_config", args=(fv_config.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This FileVault configuration cannot be deleted"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_filevault_config(self, post_event):
        fv_config = force_filevault_config()
        prev_value = fv_config.serialize_for_event()
        self.set_permissions("mdm.delete_filevaultconfig")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:filevault_config", args=(fv_config.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(FileVaultConfig.objects.filter(name=fv_config.name).count(), 0)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.filevaultconfig",
                 "pk": str(fv_config.pk),
                 "prev_value": prev_value
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_filevault_config": [str(fv_config.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
