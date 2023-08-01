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
from .utils import force_blueprint, force_filevault_config


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class FileVaultConfigManagementViewsTestCase(TestCase):
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

    # FileVault configurations

    def test_filevault_configurations_redirect(self):
        self._login_redirect(reverse("mdm:filevault_configs"))

    def test_filevault_configurations_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:filevault_configs"))
        self.assertEqual(response.status_code, 403)

    def test_filevault_configurations_no_links(self):
        fv_config = force_filevault_config()
        self._login("mdm.view_filevaultconfig")
        response = self.client.get(reverse("mdm:filevault_configs"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/filevaultconfig_list.html")
        self.assertContains(response, fv_config.name)
        self.assertNotContains(response, reverse("mdm:update_filevault_config", args=(fv_config.pk,)))
        self.assertNotContains(response, reverse("mdm:delete_filevault_config", args=(fv_config.pk,)))

    def test_filevault_configurations_all_links(self):
        fv_config1 = force_filevault_config()
        force_blueprint(filevault_config=fv_config1)
        fv_config2 = force_filevault_config()
        self._login("mdm.view_filevaultconfig", "mdm.change_filevaultconfig", "mdm.delete_filevaultconfig")
        response = self.client.get(reverse("mdm:filevault_configs"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/filevaultconfig_list.html")
        self.assertContains(response, fv_config1.name)
        self.assertContains(response, fv_config2.name)
        self.assertContains(response, reverse("mdm:update_filevault_config", args=(fv_config1.pk,)))
        self.assertNotContains(response, reverse("mdm:delete_filevault_config", args=(fv_config1.pk,)))
        self.assertContains(response, reverse("mdm:update_filevault_config", args=(fv_config2.pk,)))
        self.assertContains(response, reverse("mdm:delete_filevault_config", args=(fv_config2.pk,)))

    # create FileVault configuration

    def test_create_filevault_configuration_redirect(self):
        self._login_redirect(reverse("mdm:create_filevault_config"))

    def test_create_filevault_configuration_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:create_filevault_config"))
        self.assertEqual(response.status_code, 403)

    def test_create_filevault_configuration_get(self):
        self._login("mdm.add_filevaultconfig")
        response = self.client.get(reverse("mdm:create_filevault_config"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/filevaultconfig_form.html")
        self.assertContains(response, "Create FileVault configuration")

    def test_create_filevault_configuration_post_bypass_attempts_too_high(self):
        self._login("mdm.add_filevaultconfig")
        response = self.client.post(reverse("mdm:create_filevault_config"),
                                    {"name": get_random_string(12),
                                     "escrow_location_display_name": get_random_string(12),
                                     "at_login_only": "on",
                                     "bypass_attempts": 10000,
                                     "show_recovery_key": "on",
                                     "destroy_key_on_standby": "on",
                                     "prk_rotation_interval_days": 90},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/filevaultconfig_form.html")
        self.assertFormError(response.context["form"], "bypass_attempts",
                             'Ensure this value is less than or equal to 9999.')

    def test_create_filevault_configuration_post_prk_rotation_interval_days_too_high(self):
        self._login("mdm.add_filevaultconfig")
        response = self.client.post(reverse("mdm:create_filevault_config"),
                                    {"name": get_random_string(12),
                                     "escrow_location_display_name": get_random_string(12),
                                     "at_login_only": "on",
                                     "bypass_attempts": 1,
                                     "show_recovery_key": "on",
                                     "destroy_key_on_standby": "on",
                                     "prk_rotation_interval_days": 367},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/filevaultconfig_form.html")
        self.assertFormError(response.context["form"], "prk_rotation_interval_days",
                             'Ensure this value is less than or equal to 366.')

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_filevault_configuration_post(self, post_event):
        self._login("mdm.add_filevaultconfig", "mdm.view_filevaultconfig")
        name = get_random_string(12)
        escrow_name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:create_filevault_config"),
                                        {"name": name,
                                         "escrow_location_display_name": escrow_name,
                                         "at_login_only": "on",
                                         "bypass_attempts": 1,
                                         "show_recovery_key": "on",
                                         "destroy_key_on_standby": "on",
                                         "prk_rotation_interval_days": 90},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "mdm/filevaultconfig_detail.html")
        fv_config = response.context["object"]
        self.assertEqual(fv_config.name, name)
        self.assertEqual(fv_config.escrow_location_display_name, escrow_name)
        self.assertTrue(fv_config.at_login_only)
        self.assertEqual(fv_config.bypass_attempts, 1)
        self.assertTrue(fv_config.show_recovery_key)
        self.assertTrue(fv_config.destroy_key_on_standby)
        self.assertEqual(fv_config.prk_rotation_interval_days, 90)
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
                     "at_login_only": True,
                     "bypass_attempts": 1,
                     "show_recovery_key": True,
                     "destroy_key_on_standby": True,
                     "prk_rotation_interval_days": 90,
                     "created_at": fv_config.created_at,
                     "updated_at": fv_config.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_filevault_config": [str(fv_config.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # FileVault configuration

    def test_filevault_configuration_redirect(self):
        fv_config = force_filevault_config()
        self._login_redirect(reverse("mdm:filevault_config", args=(fv_config.pk,)))

    def test_filevault_configuration_permission_denied(self):
        fv_config = force_filevault_config()
        self._login()
        response = self.client.get(reverse("mdm:filevault_config", args=(fv_config.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_filevault_configuration_get(self):
        fv_config = force_filevault_config()
        self._login("mdm.view_filevaultconfig", "mdm.delete_filevaultconfig")
        response = self.client.get(reverse("mdm:filevault_config", args=(fv_config.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/filevaultconfig_detail.html")
        self.assertContains(response, fv_config.name)
        self.assertContains(response, reverse("mdm:delete_filevault_config", args=(fv_config.pk,)))

    def test_filevault_configuration_get_no_perm_no_delete_link(self):
        fv_config = force_filevault_config()
        self._login("mdm.view_filevaultconfig")
        response = self.client.get(reverse("mdm:filevault_config", args=(fv_config.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/filevaultconfig_detail.html")
        self.assertContains(response, fv_config.name)
        self.assertNotContains(response, reverse("mdm:delete_filevault_config", args=(fv_config.pk,)))

    def test_filevault_configuration_get_cannot_be_deleted_no_delete_link(self):
        fv_config = force_filevault_config()
        force_blueprint(filevault_config=fv_config)
        self._login("mdm.view_filevaultconfig", "mdm.delete_filevaultconfig")
        response = self.client.get(reverse("mdm:filevault_config", args=(fv_config.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/filevaultconfig_detail.html")
        self.assertContains(response, fv_config.name)
        self.assertNotContains(response, reverse("mdm:delete_filevault_config", args=(fv_config.pk,)))

    # update FileVault configuration

    def test_update_filevault_configuration_redirect(self):
        fv_config = force_filevault_config()
        self._login_redirect(reverse("mdm:update_filevault_config", args=(fv_config.pk,)))

    def test_update_filevault_configuration_permission_denied(self):
        fv_config = force_filevault_config()
        self._login()
        response = self.client.get(reverse("mdm:update_filevault_config", args=(fv_config.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_filevault_configuration_get(self):
        fv_config = force_filevault_config()
        self._login("mdm.change_filevaultconfig")
        response = self.client.get(reverse("mdm:update_filevault_config", args=(fv_config.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/filevaultconfig_form.html")
        self.assertContains(response, "Update FileVault configuration")
        self.assertContains(response, fv_config.name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_filevault_configuration_post(self, post_event):
        fv_config = force_filevault_config()
        prev_value = fv_config.serialize_for_event()
        self.assertFalse(fv_config.at_login_only)
        self.assertEqual(fv_config.bypass_attempts, -1)
        self.assertFalse(fv_config.show_recovery_key)
        self.assertFalse(fv_config.destroy_key_on_standby)
        self.assertEqual(fv_config.prk_rotation_interval_days, 0)
        self._login("mdm.change_filevaultconfig", "mdm.view_filevaultconfig")
        new_name = get_random_string(12)
        new_escrow_name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:update_filevault_config", args=(fv_config.pk,)),
                                        {"name": new_name,
                                         "escrow_location_display_name": new_escrow_name,
                                         "at_login_only": "on",
                                         "bypass_attempts": 1,
                                         "show_recovery_key": "on",
                                         "destroy_key_on_standby": "on",
                                         "prk_rotation_interval_days": 90},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "mdm/filevaultconfig_detail.html")
        fv_config2 = response.context["object"]
        self.assertEqual(fv_config2, fv_config)
        self.assertEqual(fv_config2.name, new_name)
        self.assertEqual(fv_config2.escrow_location_display_name, new_escrow_name)
        self.assertTrue(fv_config2.at_login_only)
        self.assertEqual(fv_config2.bypass_attempts, 1)
        self.assertTrue(fv_config2.show_recovery_key)
        self.assertTrue(fv_config2.destroy_key_on_standby)
        self.assertEqual(fv_config2.prk_rotation_interval_days, 90)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "mdm.filevaultconfig",
                 "pk": str(fv_config2.pk),
                 "new_value": {
                     "pk": fv_config2.pk,
                     "name": new_name,
                     "escrow_location_display_name": new_escrow_name,
                     "at_login_only": True,
                     "bypass_attempts": 1,
                     "show_recovery_key": True,
                     "destroy_key_on_standby": True,
                     "prk_rotation_interval_days": 90,
                     "created_at": fv_config2.created_at,
                     "updated_at": fv_config2.updated_at
                 },
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_filevault_config": [str(fv_config.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # delete FileVault configuration

    def test_delete_filevault_configuration_redirect(self):
        fv_config = force_filevault_config()
        self._login_redirect(reverse("mdm:delete_filevault_config", args=(fv_config.pk,)))

    def test_delete_filevault_configuration_permission_denied(self):
        fv_config = force_filevault_config()
        self._login()
        response = self.client.get(reverse("mdm:delete_filevault_config", args=(fv_config.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_filevault_configuration_404(self):
        fv_config = force_filevault_config()
        force_blueprint(filevault_config=fv_config)
        self._login("mdm.delete_filevaultconfig")
        response = self.client.get(reverse("mdm:delete_filevault_config", args=(fv_config.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_filevault_configuration_get(self):
        fv_config = force_filevault_config()
        self._login("mdm.delete_filevaultconfig")
        response = self.client.get(reverse("mdm:delete_filevault_config", args=(fv_config.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/filevaultconfig_confirm_delete.html")
        self.assertContains(response, "Delete FileVault configuration")
        self.assertContains(response, fv_config.name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_filevault_configuration_post(self, post_event):
        fv_config = force_filevault_config()
        prev_value = fv_config.serialize_for_event()
        self._login("mdm.delete_filevaultconfig", "mdm.view_filevaultconfig")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:delete_filevault_config", args=(fv_config.pk,)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "mdm/filevaultconfig_list.html")
        self.assertNotContains(response, fv_config.name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.filevaultconfig",
                 "pk": str(fv_config.pk),
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_filevault_config": [str(fv_config.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
