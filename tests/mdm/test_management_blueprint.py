from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.mdm.models import Blueprint


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class BlueprintManagementViewsTestCase(TestCase):
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

    def _force_blueprint(self):
        return Blueprint.objects.create(name=get_random_string(12))

    # blueprints

    def test_blueprints_redirect(self):
        self._login_redirect(reverse("mdm:blueprints"))

    def test_blueprints_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:blueprints"))
        self.assertEqual(response.status_code, 403)

    def test_blueprints(self):
        blueprint = self._force_blueprint()
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
        self.assertFormError(response, "form", "inventory_interval",
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
        self.assertFormError(response, "form", "inventory_interval",
                             'Ensure this value is less than or equal to 604800.')

    def test_create_blueprint_post(self):
        self._login("mdm.add_blueprint", "mdm.view_blueprint")
        name = get_random_string(12)
        response = self.client.post(reverse("mdm:create_blueprint"),
                                    {"name": name,
                                     "inventory_interval": 86401,
                                     "collect_apps": 2,
                                     "collect_certificates": 1,
                                     "collect_profiles": 0},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprint_detail.html")
        blueprint = response.context["object"]
        self.assertEqual(blueprint.name, name)
        self.assertEqual(blueprint.inventory_interval, 86401)
        self.assertEqual(blueprint.collect_apps, 2)
        self.assertEqual(blueprint.collect_certificates, 1)
        self.assertEqual(blueprint.collect_profiles, 0)
        self.assertIn("Identifier", blueprint.activation)
        self.assertIn("DeclarationsToken", blueprint.declaration_items)

    # blueprint

    def test_blueprint_redirect(self):
        blueprint = self._force_blueprint()
        self._login_redirect(reverse("mdm:blueprint", args=(blueprint.pk,)))

    def test_blueprint_permission_denied(self):
        blueprint = self._force_blueprint()
        self._login()
        response = self.client.get(reverse("mdm:blueprint", args=(blueprint.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_blueprint_get(self):
        blueprint = self._force_blueprint()
        self._login("mdm.view_blueprint")
        response = self.client.get(reverse("mdm:blueprint", args=(blueprint.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprint_detail.html")
        self.assertContains(response, blueprint.name)

    # update blueprint

    def test_update_blueprint_redirect(self):
        blueprint = self._force_blueprint()
        self._login_redirect(reverse("mdm:update_blueprint", args=(blueprint.pk,)))

    def test_update_blueprint_permission_denied(self):
        blueprint = self._force_blueprint()
        self._login()
        response = self.client.get(reverse("mdm:update_blueprint", args=(blueprint.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_blueprint_get(self):
        blueprint = self._force_blueprint()
        self._login("mdm.change_blueprint")
        response = self.client.get(reverse("mdm:update_blueprint", args=(blueprint.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprint_form.html")
        self.assertContains(response, "Update blueprint")
        self.assertContains(response, blueprint.name)

    def test_update_blueprint_post(self):
        blueprint = self._force_blueprint()
        self.assertEqual(blueprint.inventory_interval, 86400)
        self.assertEqual(blueprint.collect_apps, 0)
        self.assertEqual(blueprint.collect_certificates, 0)
        self.assertEqual(blueprint.collect_profiles, 0)
        self._login("mdm.change_blueprint", "mdm.view_blueprint")
        new_name = get_random_string(12)
        response = self.client.post(reverse("mdm:update_blueprint", args=(blueprint.pk,)),
                                    {"name": new_name,
                                     "inventory_interval": 14401,
                                     "collect_apps": 1,
                                     "collect_certificates": 1,
                                     "collect_profiles": 2},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprint_detail.html")
        blueprint2 = response.context["object"]
        self.assertEqual(blueprint2, blueprint)
        self.assertEqual(blueprint2.name, new_name)
        self.assertEqual(blueprint2.inventory_interval, 14401)
        self.assertEqual(blueprint2.collect_apps, 1)
        self.assertEqual(blueprint2.collect_certificates, 1)
        self.assertEqual(blueprint2.collect_profiles, 2)
        self.assertIn("Identifier", blueprint2.activation)
        self.assertIn("DeclarationsToken", blueprint2.declaration_items)
