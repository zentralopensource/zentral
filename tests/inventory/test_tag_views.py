from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from zentral.contrib.inventory.models import Tag
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MacOSAppsViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string())
        cls.group = Group.objects.create(name=get_random_string())
        cls.user.groups.set([cls.group])

    # utility methods

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

    def _force_tag(self, name=None):
        return Tag.objects.create(name=name or get_random_string())

    # tags

    def test_tags_redirect(self):
        self._login_redirect(reverse("inventory:tags"))

    def test_tags_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:tags"))
        self.assertEqual(response.status_code, 403)

    def test_tags(self):
        tag = self._force_tag()
        self._login("inventory.view_tag")
        response = self.client.get(reverse("inventory:tags"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, tag.name)
        self.assertTemplateUsed(response, "inventory/tag_index.html")

    # create tag

    def test_create_tag_redirect(self):
        self._login_redirect(reverse("inventory:create_tag"))

    def test_create_tag_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:create_tag"))
        self.assertEqual(response.status_code, 403)

    def test_create_tag_get(self):
        self._login("inventory.add_tag")
        response = self.client.get(reverse("inventory:create_tag"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/tag_form.html")

    def test_create_tag_post_name_exists(self):
        tag = self._force_tag()
        self._login("inventory.add_tag")
        response = self.client.post(reverse("inventory:create_tag"),
                                    {"name": tag.name})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/tag_form.html")
        self.assertFormError(response, "form", "name", "A tag with this name already exists.")

    def test_create_tag_post_conflicting_slug(self):
        tag = self._force_tag(get_random_string() + " " + get_random_string())
        self._login("inventory.add_tag")
        response = self.client.post(reverse("inventory:create_tag"),
                                    {"name": tag.name.replace(" ", "-")})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/tag_form.html")
        self.assertFormError(response, "form", "name", "A tag with a conflicting slug already exists.")

    def test_create_tag_post(self):
        self._login("inventory.add_tag", "inventory.view_tag")
        name = get_random_string()
        color = get_random_string(6, "abcedf0123456789")
        response = self.client.post(reverse("inventory:create_tag"),
                                    {"name": name,
                                     "color": color}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/tag_index.html")
        self.assertContains(response, name)
        self.assertContains(response, color)

    # update tag

    def test_update_tag_redirect(self):
        tag = self._force_tag()
        self._login_redirect(reverse("inventory:update_tag", args=(tag.pk,)))

    def test_update_tag_permission_denied(self):
        tag = self._force_tag()
        self._login()
        response = self.client.get(reverse("inventory:update_tag", args=(tag.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_tag_get(self):
        tag = self._force_tag()
        self._login("inventory.change_tag")
        response = self.client.get(reverse("inventory:update_tag", args=(tag.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/tag_form.html")
        self.assertContains(response, tag.name)

    def test_update_tag_post_name_exists(self):
        tag0 = self._force_tag()
        tag = self._force_tag()
        self._login("inventory.change_tag")
        response = self.client.post(reverse("inventory:update_tag", args=(tag.pk,)),
                                    {"name": tag0.name})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/tag_form.html")
        self.assertFormError(response, "form", "name", "A tag with this name already exists.")

    def test_update_tag_post_conflicting_slug(self):
        tag0 = self._force_tag(get_random_string() + " " + get_random_string())
        tag = self._force_tag()
        self._login("inventory.change_tag")
        response = self.client.post(reverse("inventory:update_tag", args=(tag.pk,)),
                                    {"name": tag0.name.replace(" ", "-")})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/tag_form.html")
        self.assertFormError(response, "form", "name", "A tag with a conflicting slug already exists.")

    def test_update_tag_post(self):
        tag = self._force_tag()
        name = get_random_string()
        color = get_random_string(6, "abcedf0123456789")
        self._login("inventory.change_tag", "inventory.view_tag")
        response = self.client.post(reverse("inventory:update_tag", args=(tag.pk,)),
                                    {"name": name,
                                     "color": color}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/tag_index.html")
        self.assertContains(response, name)
        tag.refresh_from_db()
        self.assertEqual(tag.name, name)
        self.assertEqual(tag.color, color)
