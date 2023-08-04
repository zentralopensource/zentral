from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.core.events.base import AuditEvent
from .utils import force_blueprint, force_recovery_password_config


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class RecoveryPasswordConfigManagementViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # utiliy methods

    def _login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def _login(self, *permissions):
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
        self.client.force_login(self.user)

    # recovery password configurations

    def test_recovery_password_configurations_redirect(self):
        self._login_redirect(reverse("mdm:recovery_password_configs"))

    def test_recovery_password_configurations_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:recovery_password_configs"))
        self.assertEqual(response.status_code, 403)

    def test_recovery_password_configurations_no_links(self):
        rp_config = force_recovery_password_config()
        self._login("mdm.view_recoverypasswordconfig")
        response = self.client.get(reverse("mdm:recovery_password_configs"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/recoverypasswordconfig_list.html")
        self.assertContains(response, rp_config.name)
        self.assertNotContains(response, reverse("mdm:update_recovery_password_config", args=(rp_config.pk,)))
        self.assertNotContains(response, reverse("mdm:delete_recovery_password_config", args=(rp_config.pk,)))

    def test_recovery_password_configurations_all_links(self):
        rp_config1 = force_recovery_password_config()
        force_blueprint(recovery_password_config=rp_config1)
        rp_config2 = force_recovery_password_config()
        self._login("mdm.view_recoverypasswordconfig",
                    "mdm.change_recoverypasswordconfig",
                    "mdm.delete_recoverypasswordconfig")
        response = self.client.get(reverse("mdm:recovery_password_configs"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/recoverypasswordconfig_list.html")
        self.assertContains(response, rp_config1.name)
        self.assertContains(response, rp_config2.name)
        self.assertContains(response, reverse("mdm:update_recovery_password_config", args=(rp_config1.pk,)))
        self.assertNotContains(response, reverse("mdm:delete_recovery_password_config", args=(rp_config1.pk,)))
        self.assertContains(response, reverse("mdm:update_recovery_password_config", args=(rp_config2.pk,)))
        self.assertContains(response, reverse("mdm:delete_recovery_password_config", args=(rp_config2.pk,)))

    # create recovery password configuration

    def test_create_recovery_password_configuration_redirect(self):
        self._login_redirect(reverse("mdm:create_recovery_password_config"))

    def test_create_recovery_password_configuration_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:create_recovery_password_config"))
        self.assertEqual(response.status_code, 403)

    def test_create_recovery_password_configuration_get(self):
        self._login("mdm.add_recoverypasswordconfig")
        response = self.client.get(reverse("mdm:create_recovery_password_config"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/recoverypasswordconfig_form.html")
        self.assertContains(response, "Create recovery password configuration")

    def test_create_recovery_password_configuration_static_password_required_error(self):
        self._login("mdm.add_recoverypasswordconfig")
        response = self.client.post(reverse("mdm:create_recovery_password_config"),
                                    {"name": get_random_string(12),
                                     "dynamic_password": False,
                                     "rotation_interval_days": 0,
                                     "rotate_firmware_password": False},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/recoverypasswordconfig_form.html")
        self.assertFormError(response.context["form"], "static_password",
                             'This field is required when not using dynamic passwords.')

    def test_create_recovery_password_configuration_static_password_too_short_error(self):
        self._login("mdm.add_recoverypasswordconfig")
        response = self.client.post(reverse("mdm:create_recovery_password_config"),
                                    {"name": get_random_string(12),
                                     "dynamic_password": False,
                                     "static_password": "1",
                                     "rotation_interval_days": 0,
                                     "rotate_firmware_password": False},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/recoverypasswordconfig_form.html")
        self.assertFormError(response.context["form"], "static_password",
                             'The password must be at least 8 characters long.')

    def test_create_recovery_password_configuration_static_password_too_long_error(self):
        self._login("mdm.add_recoverypasswordconfig")
        response = self.client.post(reverse("mdm:create_recovery_password_config"),
                                    {"name": get_random_string(12),
                                     "dynamic_password": False,
                                     "static_password": 33 * "1",
                                     "rotation_interval_days": 0,
                                     "rotate_firmware_password": False},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/recoverypasswordconfig_form.html")
        self.assertFormError(response.context["form"], "static_password",
                             'The password must be at most 32 characters long.')

    def test_create_recovery_password_configuration_static_password_non_ascii(self):
        self._login("mdm.add_recoverypasswordconfig")
        response = self.client.post(reverse("mdm:create_recovery_password_config"),
                                    {"name": get_random_string(12),
                                     "dynamic_password": False,
                                     "static_password": 8 * "é",
                                     "rotation_interval_days": 0,
                                     "rotate_firmware_password": False},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/recoverypasswordconfig_form.html")
        self.assertFormError(
            response.context["form"],
            "static_password",
            "The characters in this value must consist of low-ASCII, printable characters (0x20 through 0x7E) "
            "to ensure that all characters are enterable on the EFI login screen."
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_recovery_password_configuration_post(self, post_event):
        self._login("mdm.add_recoverypasswordconfig", "mdm.view_recoverypasswordconfig")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:create_recovery_password_config"),
                                        {"name": name,
                                         "dynamic_password": False,
                                         "static_password": "12345678",
                                         "rotation_interval_days": 90,
                                         "rotate_firmware_password": True},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "mdm/recoverypasswordconfig_detail.html")
        rp_config = response.context["object"]
        self.assertEqual(rp_config.name, name)
        self.assertFalse(rp_config.dynamic_password)
        self.assertEqual(rp_config.get_static_password(), "12345678")
        self.assertEqual(rp_config.rotation_interval_days, 90)
        self.assertTrue(rp_config.rotate_firmware_password)
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
                     "rotation_interval_days": 90,
                     "rotate_firmware_password": True,
                     "created_at": rp_config.created_at,
                     "updated_at": rp_config.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_recovery_password_config": [str(rp_config.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # recovery password configuration

    def test_recovery_password_configuration_redirect(self):
        rp_config = force_recovery_password_config()
        self._login_redirect(reverse("mdm:recovery_password_config", args=(rp_config.pk,)))

    def test_recovery_password_configuration_permission_denied(self):
        rp_config = force_recovery_password_config()
        self._login()
        response = self.client.get(reverse("mdm:recovery_password_config", args=(rp_config.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_recovery_password_configuration_get(self):
        rp_config = force_recovery_password_config()
        self._login("mdm.view_recoverypasswordconfig", "mdm.delete_recoverypasswordconfig")
        response = self.client.get(reverse("mdm:recovery_password_config", args=(rp_config.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/recoverypasswordconfig_detail.html")
        self.assertContains(response, rp_config.name)
        self.assertContains(response, reverse("mdm:delete_recovery_password_config", args=(rp_config.pk,)))

    def test_recovery_password_configuration_get_no_perm_no_delete_link(self):
        rp_config = force_recovery_password_config()
        self._login("mdm.view_recoverypasswordconfig")
        response = self.client.get(reverse("mdm:recovery_password_config", args=(rp_config.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/recoverypasswordconfig_detail.html")
        self.assertContains(response, rp_config.name)
        self.assertNotContains(response, reverse("mdm:delete_recovery_password_config", args=(rp_config.pk,)))

    def test_recovery_password_configuration_get_cannot_be_deleted_no_delete_link(self):
        rp_config = force_recovery_password_config()
        force_blueprint(recovery_password_config=rp_config)
        self._login("mdm.view_recoverypasswordconfig", "mdm.delete_recoverypasswordconfig")
        response = self.client.get(reverse("mdm:recovery_password_config", args=(rp_config.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/recoverypasswordconfig_detail.html")
        self.assertContains(response, rp_config.name)
        self.assertNotContains(response, reverse("mdm:delete_recovery_password_config", args=(rp_config.pk,)))

    # update recovery password configuration

    def test_update_recovery_password_configuration_redirect(self):
        rp_config = force_recovery_password_config()
        self._login_redirect(reverse("mdm:update_recovery_password_config", args=(rp_config.pk,)))

    def test_update_recovery_password_configuration_permission_denied(self):
        rp_config = force_recovery_password_config()
        self._login()
        response = self.client.get(reverse("mdm:update_recovery_password_config", args=(rp_config.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_recovery_password_configuration_get(self):
        rp_config = force_recovery_password_config()
        self._login("mdm.change_recoverypasswordconfig")
        response = self.client.get(reverse("mdm:update_recovery_password_config", args=(rp_config.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/recoverypasswordconfig_form.html")
        self.assertContains(response, "Update recovery password configuration")
        self.assertContains(response, rp_config.name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_recovery_password_configuration_post(self, post_event):
        rp_config = force_recovery_password_config()
        prev_value = rp_config.serialize_for_event()
        self.assertTrue(rp_config.dynamic_password)
        self.assertIsNone(rp_config.static_password)
        self.assertEqual(rp_config.rotation_interval_days, 0)
        self.assertFalse(rp_config.rotate_firmware_password)
        self._login("mdm.change_recoverypasswordconfig", "mdm.view_recoverypasswordconfig")
        new_name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:update_recovery_password_config", args=(rp_config.pk,)),
                                        {"name": new_name,
                                         "dynamic_password": False,
                                         "static_password": "12345678",
                                         "rotation_interval_days": 90,
                                         "rotate_firmware_password": True},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "mdm/recoverypasswordconfig_detail.html")
        rp_config2 = response.context["object"]
        self.assertEqual(rp_config2, rp_config)
        self.assertEqual(rp_config2.name, new_name)
        self.assertFalse(rp_config2.dynamic_password)
        self.assertEqual(rp_config2.get_static_password(), "12345678")
        self.assertEqual(rp_config2.rotation_interval_days, 90)
        self.assertTrue(rp_config2.rotate_firmware_password)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "mdm.recoverypasswordconfig",
                 "pk": str(rp_config2.pk),
                 "new_value": {
                     "pk": rp_config2.pk,
                     "name": new_name,
                     "dynamic_password": False,
                     "rotation_interval_days": 90,
                     "rotate_firmware_password": True,
                     "created_at": rp_config2.created_at,
                     "updated_at": rp_config2.updated_at
                 },
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_recovery_password_config": [str(rp_config.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # delete recovery password configuration

    def test_delete_recovery_password_configuration_redirect(self):
        rp_config = force_recovery_password_config()
        self._login_redirect(reverse("mdm:delete_recovery_password_config", args=(rp_config.pk,)))

    def test_delete_recovery_password_configuration_permission_denied(self):
        rp_config = force_recovery_password_config()
        self._login()
        response = self.client.get(reverse("mdm:delete_recovery_password_config", args=(rp_config.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_recovery_password_configuration_404(self):
        rp_config = force_recovery_password_config()
        force_blueprint(recovery_password_config=rp_config)
        self._login("mdm.delete_recoverypasswordconfig")
        response = self.client.get(reverse("mdm:delete_recovery_password_config", args=(rp_config.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_recovery_password_configuration_get(self):
        rp_config = force_recovery_password_config()
        self._login("mdm.delete_recoverypasswordconfig")
        response = self.client.get(reverse("mdm:delete_recovery_password_config", args=(rp_config.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/recoverypasswordconfig_confirm_delete.html")
        self.assertContains(response, "Delete recovery password configuration")
        self.assertContains(response, rp_config.name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_recovery_password_configuration_post(self, post_event):
        rp_config = force_recovery_password_config()
        prev_value = rp_config.serialize_for_event()
        self._login("mdm.delete_recoverypasswordconfig", "mdm.view_recoverypasswordconfig")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:delete_recovery_password_config", args=(rp_config.pk,)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "mdm/recoverypasswordconfig_list.html")
        self.assertNotContains(response, rp_config.name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.recoverypasswordconfig",
                 "pk": str(rp_config.pk),
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_recovery_password_config": [str(rp_config.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
