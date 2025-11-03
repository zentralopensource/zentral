from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import APIToken, User
from zentral.contrib.mdm.models import RecoveryPasswordConfig
from zentral.core.events.base import AuditEvent
from .utils import force_blueprint, force_recovery_password_config


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MDMRecoveryPasswordConfigsAPIViewsTestCase(TestCase):
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

    # list recovery password configs

    def test_list_recovery_password_configs_unauthorized(self):
        response = self.get(reverse("mdm_api:recovery_password_configs"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_recovery_password_configs_permission_denied(self):
        response = self.get(reverse("mdm_api:recovery_password_configs"))
        self.assertEqual(response.status_code, 403)

    def test_list_recovery_password_configs(self):
        rp_config = force_recovery_password_config()
        self.set_permissions("mdm.view_recoverypasswordconfig")
        response = self.get(reverse("mdm_api:recovery_password_configs"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'id': rp_config.pk,
              'name': rp_config.name,
              'dynamic_password': rp_config.dynamic_password,
              'static_password': rp_config.static_password,
              'rotation_interval_days': 0,
              'rotate_firmware_password': False,
              'created_at': rp_config.created_at.isoformat(),
              'updated_at': rp_config.updated_at.isoformat()}]
        )

    def test_list_recovery_password_configs_name_filter(self):
        force_recovery_password_config()
        static_password = get_random_string(12)
        rp_config = force_recovery_password_config(static_password=static_password)
        self.set_permissions("mdm.view_recoverypasswordconfig")
        response = self.get(reverse("mdm_api:recovery_password_configs"), data={"name": rp_config.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'id': rp_config.pk,
              'name': rp_config.name,
              'dynamic_password': rp_config.dynamic_password,
              'static_password': static_password,
              'rotation_interval_days': 0,
              'rotate_firmware_password': False,
              'created_at': rp_config.created_at.isoformat(),
              'updated_at': rp_config.updated_at.isoformat()}]
        )

    # get recovery password config

    def test_get_recovery_password_config_unauthorized(self):
        rp_config = force_recovery_password_config()
        response = self.get(reverse("mdm_api:recovery_password_config", args=(rp_config.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_recovery_password_config_permission_denied(self):
        rp_config = force_recovery_password_config()
        response = self.get(reverse("mdm_api:blueprint", args=(rp_config.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_recovery_password_config(self):
        force_recovery_password_config()
        static_password = get_random_string(12)
        rp_config = force_recovery_password_config(rotation_interval_days=17, static_password=static_password)
        self.set_permissions("mdm.view_recoverypasswordconfig")
        response = self.get(reverse("mdm_api:recovery_password_config", args=(rp_config.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'id': rp_config.pk,
             'name': rp_config.name,
             'dynamic_password': rp_config.dynamic_password,
             'static_password': static_password,
             'rotation_interval_days': 17,
             'rotate_firmware_password': False,
             'created_at': rp_config.created_at.isoformat(),
             'updated_at': rp_config.updated_at.isoformat()}
        )

    # create recovery password config

    def test_create_recovery_password_config_unauthorized(self):
        response = self.post(reverse("mdm_api:recovery_password_configs"),
                             {"name": get_random_string(12)},
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_recovery_password_config_permission_denied(self):
        response = self.post(reverse("mdm_api:recovery_password_configs"),
                             {"name": get_random_string(12)})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_recovery_password_config(self, post_event):
        self.set_permissions("mdm.add_recoverypasswordconfig")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:recovery_password_configs"),
                                 {"name": name,
                                  "dynamic_password": False,
                                  "static_password": "12345678"})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        rp_config = RecoveryPasswordConfig.objects.get(name=name)
        self.assertEqual(rp_config.get_static_password(), "12345678")
        self.assertEqual(
            response.json(),
            {'id': rp_config.pk,
             'name': rp_config.name,
             'dynamic_password': False,
             'static_password': "12345678",
             'rotation_interval_days': 0,
             'rotate_firmware_password': False,
             'created_at': rp_config.created_at.isoformat(),
             'updated_at': rp_config.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "mdm.recoverypasswordconfig",
                 "pk": str(rp_config.pk),
                 "new_value": {
                     "pk": rp_config.pk,
                     "name": name,
                     "dynamic_password": False,
                     "rotation_interval_days": 0,
                     "rotate_firmware_password": False,
                     "created_at": rp_config.created_at,
                     "updated_at": rp_config.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_recovery_password_config": [str(rp_config.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # update Recovery password config

    def test_update_recovery_password_config_unauthorized(self):
        rp_config = force_recovery_password_config()
        response = self.put(reverse("mdm_api:recovery_password_config", args=(rp_config.pk,)),
                            {"name": get_random_string(12)},
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_recovery_password_config_permission_denied(self):
        rp_config = force_recovery_password_config()
        response = self.put(reverse("mdm_api:recovery_password_config", args=(rp_config.pk,)),
                            {"name": get_random_string(12)})
        self.assertEqual(response.status_code, 403)

    def test_update_recovery_password_dynamic_and_static_password_error(self):
        rp_config = force_recovery_password_config()
        self.set_permissions("mdm.change_recoverypasswordconfig")
        response = self.put(reverse("mdm_api:recovery_password_config", args=(rp_config.pk,)),
                            {"name": get_random_string(12),
                             "dynamic_password": True,
                             "static_password": get_random_string(12),
                             "rotation_interval_days": 0,
                             "rotate_firmware_password": True})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'static_password': ['Cannot be set when dynamic_password is true'],
             'rotate_firmware_password': ['Cannot be set without a rotation interval']}
        )

    def test_update_recovery_password_required_static_password_error(self):
        rp_config = force_recovery_password_config()
        self.set_permissions("mdm.change_recoverypasswordconfig")
        response = self.put(reverse("mdm_api:recovery_password_config", args=(rp_config.pk,)),
                            {"name": get_random_string(12),
                             "dynamic_password": False,
                             "rotation_interval_days": 17,
                             "rotate_firmware_password": True})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'static_password': ['Required when dynamic_password is false'],
             'rotation_interval_days': ['Cannot be set with a static password'],
             'rotate_firmware_password': ['Cannot be set with a static password']}
        )

    def test_update_recovery_password_required_static_rotation_error(self):
        rp_config = force_recovery_password_config()
        self.set_permissions("mdm.change_recoverypasswordconfig")
        response = self.put(reverse("mdm_api:recovery_password_config", args=(rp_config.pk,)),
                            {"name": get_random_string(12),
                             "dynamic_password": False,
                             "static_password": "1234568",
                             "rotation_interval_days": 17,
                             "rotate_firmware_password": True})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'rotation_interval_days': ['Cannot be set with a static password'],
            'rotate_firmware_password': ['Cannot be set with a static password']}
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_recovery_password_config(self, post_event):
        rp_config = force_recovery_password_config()
        prev_value = rp_config.serialize_for_event()
        self.set_permissions("mdm.change_recoverypasswordconfig")
        new_name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(reverse("mdm_api:recovery_password_config", args=(rp_config.pk,)),
                                {"name": new_name,
                                 "dynamic_password": True,
                                 "rotation_interval_days": 17,
                                 "rotate_firmware_password": True})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        rp_config.refresh_from_db()
        self.assertEqual(rp_config.name, new_name)
        self.assertTrue(rp_config.dynamic_password)
        self.assertEqual(rp_config.rotation_interval_days, 17)
        self.assertTrue(rp_config.rotate_firmware_password)
        self.assertEqual(
            response.json(),
            {'id': rp_config.pk,
             'name': new_name,
             'dynamic_password': True,
             'static_password': None,
             'rotation_interval_days': 17,
             'rotate_firmware_password': True,
             'created_at': rp_config.created_at.isoformat(),
             'updated_at': rp_config.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "mdm.recoverypasswordconfig",
                 "pk": str(rp_config.pk),
                 "new_value": {
                     "pk": rp_config.pk,
                     "name": new_name,
                     "dynamic_password": True,
                     "rotation_interval_days": 17,
                     "rotate_firmware_password": True,
                     "created_at": rp_config.created_at,
                     "updated_at": rp_config.updated_at
                 },
                 "prev_value": prev_value
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_recovery_password_config": [str(rp_config.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # delete Recovery password config

    def test_delete_recovery_password_config_unauthorized(self):
        rp_config = force_recovery_password_config()
        response = self.delete(reverse("mdm_api:recovery_password_config", args=(rp_config.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_recovery_password_config_permission_denied(self):
        rp_config = force_recovery_password_config()
        response = self.delete(reverse("mdm_api:recovery_password_config", args=(rp_config.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_recovery_password_config_cannot_be_deleted(self):
        rp_config = force_recovery_password_config()
        force_blueprint(recovery_password_config=rp_config)
        self.set_permissions("mdm.delete_recoverypasswordconfig")
        response = self.delete(reverse("mdm_api:recovery_password_config", args=(rp_config.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This recovery password configuration cannot be deleted"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_recovery_password_config(self, post_event):
        rp_config = force_recovery_password_config()
        prev_value = rp_config.serialize_for_event()
        self.set_permissions("mdm.delete_recoverypasswordconfig")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:recovery_password_config", args=(rp_config.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(RecoveryPasswordConfig.objects.filter(name=rp_config.name).count(), 0)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.recoverypasswordconfig",
                 "pk": str(rp_config.pk),
                 "prev_value": prev_value
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_recovery_password_config": [str(rp_config.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
