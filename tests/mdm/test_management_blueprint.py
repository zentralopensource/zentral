from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.core.events.base import AuditEvent
from .utils import (force_blueprint, force_blueprint_artifact,
                    force_filevault_config, force_location,
                    force_recovery_password_config, force_software_update_enforcement)


class BlueprintManagementViewsTestCase(TestCase):
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

    # blueprints

    def test_blueprints_redirect(self):
        self._login_redirect(reverse("mdm:blueprints"))

    def test_blueprints_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:blueprints"))
        self.assertEqual(response.status_code, 403)

    def test_blueprints(self):
        blueprint = force_blueprint()
        self._login("mdm.view_blueprint")
        response = self.client.get(reverse("mdm:blueprints"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprint_list.html")
        self.assertContains(response, blueprint.name)

    # create blueprint

    def test_create_blueprint_redirect(self):
        self._login_redirect(reverse("mdm:create_blueprint"))

    def test_create_blueprint_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:create_blueprint"))
        self.assertEqual(response.status_code, 403)

    def test_create_blueprint_get(self):
        self._login("mdm.add_blueprint")
        response = self.client.get(reverse("mdm:create_blueprint"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprint_form.html")
        self.assertContains(response, "Create blueprint")

    def test_create_blueprint_post_inventory_interval_too_low(self):
        self._login("mdm.add_blueprint")
        response = self.client.post(reverse("mdm:create_blueprint"),
                                    {"name": get_random_string(12),
                                     "inventory_interval": 10,
                                     "collect_apps": 2,
                                     "collect_certificates": 1,
                                     "collect_profiles": 0},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprint_form.html")
        self.assertFormError(response.context["form"], "inventory_interval",
                             'Ensure this value is greater than or equal to 14400.')

    def test_create_blueprint_post_inventory_interval_too_high(self):
        self._login("mdm.add_blueprint")
        response = self.client.post(reverse("mdm:create_blueprint"),
                                    {"name": get_random_string(12),
                                     "inventory_interval": 100000000000,
                                     "collect_apps": 2,
                                     "collect_certificates": 1,
                                     "collect_profiles": 0},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprint_form.html")
        self.assertFormError(response.context["form"], "inventory_interval",
                             'Ensure this value is less than or equal to 604800.')

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_blueprint_post(self, post_event):
        self._login("mdm.add_blueprint", "mdm.view_blueprint")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:create_blueprint"),
                                        {"name": name,
                                         "inventory_interval": 86401,
                                         "collect_apps": 2,
                                         "collect_certificates": 1,
                                         "collect_profiles": 0,
                                         "legacy_profiles_via_ddm": "on"},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "mdm/blueprint_detail.html")
        blueprint = response.context["object"]
        self.assertEqual(blueprint.name, name)
        self.assertEqual(blueprint.inventory_interval, 86401)
        self.assertEqual(blueprint.collect_apps, 2)
        self.assertEqual(blueprint.collect_certificates, 1)
        self.assertEqual(blueprint.collect_profiles, 0)
        self.assertTrue(blueprint.legacy_profiles_via_ddm)
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
                     "inventory_interval": 86401,
                     "collect_apps": "ALL",
                     "collect_certificates": "MANAGED_ONLY",
                     "collect_profiles": "NO",
                     "legacy_profiles_via_ddm": True,
                     "created_at": blueprint.created_at,
                     "updated_at": blueprint.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_blueprint": [str(blueprint.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # blueprint

    def test_blueprint_redirect(self):
        blueprint = force_blueprint()
        self._login_redirect(reverse("mdm:blueprint", args=(blueprint.pk,)))

    def test_blueprint_permission_denied(self):
        blueprint = force_blueprint()
        self._login()
        response = self.client.get(reverse("mdm:blueprint", args=(blueprint.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_blueprint_get_all_links(self):
        fv_config = force_filevault_config()
        rp_config = force_recovery_password_config()
        sue = force_software_update_enforcement()
        blueprint = force_blueprint(
            filevault_config=fv_config,
            recovery_password_config=rp_config,
            software_update_enforcement=sue,
        )
        self.assertTrue(blueprint.can_be_deleted())
        self._login("mdm.view_blueprint",
                    "mdm.delete_blueprint",
                    "mdm.view_filevaultconfig",
                    "mdm.view_recoverypasswordconfig",
                    "mdm.view_softwareupdateenforcement")
        response = self.client.get(reverse("mdm:blueprint", args=(blueprint.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprint_detail.html")
        self.assertContains(response, blueprint.name)
        self.assertContains(response, reverse("mdm:delete_blueprint", args=(blueprint.pk,)))
        self.assertContains(response, fv_config.get_absolute_url())
        self.assertContains(response, rp_config.get_absolute_url())
        self.assertContains(response, sue.get_absolute_url())

    def test_blueprint_get_no_perms_no_links(self):
        fv_config = force_filevault_config()
        rp_config = force_recovery_password_config()
        sue = force_software_update_enforcement()
        blueprint = force_blueprint(
            filevault_config=fv_config,
            recovery_password_config=rp_config,
            software_update_enforcement=sue,
        )
        self.assertTrue(blueprint.can_be_deleted())
        self._login("mdm.view_blueprint")
        response = self.client.get(reverse("mdm:blueprint", args=(blueprint.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprint_detail.html")
        self.assertContains(response, blueprint.name)
        self.assertNotContains(response, reverse("mdm:delete_blueprint", args=(blueprint.pk,)))
        self.assertNotContains(response, fv_config.get_absolute_url())
        self.assertNotContains(response, rp_config.get_absolute_url())
        self.assertNotContains(response, sue.get_absolute_url())

    def test_blueprint_get_cannot_be_deleted_no_delete_link(self):
        blueprint = force_blueprint()
        force_blueprint_artifact(blueprint=blueprint)
        self.assertFalse(blueprint.can_be_deleted())
        self._login("mdm.view_blueprint", "mdm.delete_blueprint")
        response = self.client.get(reverse("mdm:blueprint", args=(blueprint.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprint_detail.html")
        self.assertNotContains(response, reverse("mdm:delete_blueprint", args=(blueprint.pk,)))

    # update blueprint

    def test_update_blueprint_redirect(self):
        blueprint = force_blueprint()
        self._login_redirect(reverse("mdm:update_blueprint", args=(blueprint.pk,)))

    def test_update_blueprint_permission_denied(self):
        blueprint = force_blueprint()
        self._login()
        response = self.client.get(reverse("mdm:update_blueprint", args=(blueprint.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_blueprint_get(self):
        blueprint = force_blueprint()
        self._login("mdm.change_blueprint")
        response = self.client.get(reverse("mdm:update_blueprint", args=(blueprint.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprint_form.html")
        self.assertContains(response, "Update blueprint")
        self.assertContains(response, blueprint.name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_blueprint_post(self, post_event):
        blueprint = force_blueprint()
        prev_value = blueprint.serialize_for_event()
        self.assertEqual(blueprint.inventory_interval, 86400)
        self.assertEqual(blueprint.collect_apps, 0)
        self.assertEqual(blueprint.collect_certificates, 0)
        self.assertEqual(blueprint.collect_profiles, 0)
        self._login("mdm.change_blueprint", "mdm.view_blueprint")
        new_name = get_random_string(12)
        location = force_location()
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:update_blueprint", args=(blueprint.pk,)),
                                        {"name": new_name,
                                         "inventory_interval": 14401,
                                         "collect_apps": 1,
                                         "collect_certificates": 1,
                                         "collect_profiles": 2,
                                         "default_location": location.pk},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "mdm/blueprint_detail.html")
        blueprint2 = response.context["object"]
        self.assertEqual(blueprint2, blueprint)
        self.assertEqual(blueprint2.name, new_name)
        self.assertEqual(blueprint2.inventory_interval, 14401)
        self.assertEqual(blueprint2.collect_apps, 1)
        self.assertEqual(blueprint2.collect_certificates, 1)
        self.assertEqual(blueprint2.collect_profiles, 2)
        self.assertEqual(blueprint2.default_location, location)
        self.assertFalse(blueprint2.legacy_profiles_via_ddm)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "mdm.blueprint",
                 "pk": str(blueprint2.pk),
                 "new_value": {
                     "pk": blueprint2.pk,
                     "name": new_name,
                     "inventory_interval": 14401,
                     "collect_apps": "MANAGED_ONLY",
                     "collect_certificates": "MANAGED_ONLY",
                     "collect_profiles": "ALL",
                     "default_location": {"pk": location.pk, "mdm_info_id": str(location.mdm_info_id)},
                     "legacy_profiles_via_ddm": False,
                     "created_at": blueprint2.created_at,
                     "updated_at": blueprint2.updated_at
                 },
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_blueprint": [str(blueprint.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # delete blueprint

    def test_delete_blueprint_redirect(self):
        blueprint = force_blueprint()
        self._login_redirect(reverse("mdm:delete_blueprint", args=(blueprint.pk,)))

    def test_delete_blueprint_permission_denied(self):
        blueprint = force_blueprint()
        self._login()
        response = self.client.get(reverse("mdm:delete_blueprint", args=(blueprint.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_blueprint_get(self):
        blueprint = force_blueprint()
        self._login("mdm.delete_blueprint")
        response = self.client.get(reverse("mdm:delete_blueprint", args=(blueprint.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprint_confirm_delete.html")
        self.assertContains(response, "Delete blueprint")
        self.assertContains(response, blueprint.name)

    def test_delete_blueprint_404(self):
        blueprint = force_blueprint()
        force_blueprint_artifact(blueprint=blueprint)
        self.assertFalse(blueprint.can_be_deleted())
        self._login("mdm.delete_blueprint")
        response = self.client.get(reverse("mdm:delete_blueprint", args=(blueprint.pk,)))
        self.assertEqual(response.status_code, 404)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_blueprint_post(self, post_event):
        blueprint = force_blueprint()
        prev_value = blueprint.serialize_for_event()
        self._login("mdm.delete_blueprint", "mdm.view_blueprint")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:delete_blueprint", args=(blueprint.pk,)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "mdm/blueprint_list.html")
        self.assertNotContains(response, blueprint.name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.blueprint",
                 "pk": str(blueprint.pk),
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_blueprint": [str(blueprint.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
