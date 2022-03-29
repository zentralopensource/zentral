from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.osquery.models import FileCategory


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class OsquerySetupFileCategoriesViewsTestCase(TestCase):
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

    def _force_file_category(self):
        return FileCategory.objects.create(
            name=get_random_string(12),
            file_paths=[get_random_string(16) for i in range(3)]
        )

    # create file_category

    def test_create_file_category_redirect(self):
        self._login_redirect(reverse("osquery:create_file_category"))

    def test_create_file_category_permission_denied(self):
        self._login()
        response = self.client.get(reverse("osquery:create_file_category"))
        self.assertEqual(response.status_code, 403)

    def test_create_file_category_get(self):
        self._login("osquery.add_filecategory")
        response = self.client.get(reverse("osquery:create_file_category"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/filecategory_form.html")
        self.assertContains(response, "Create File category")

    def test_create_file_category_post(self):
        self._login("osquery.add_filecategory", "osquery.view_filecategory")
        file_category_name = get_random_string(64)
        response = self.client.post(reverse("osquery:create_file_category"),
                                    {"name": file_category_name,
                                     "file_paths": "yolo, fomo"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/filecategory_detail.html")
        self.assertContains(response, file_category_name)
        file_category = response.context["object"]
        self.assertEqual(file_category.name, file_category_name)
        self.assertEqual(file_category.file_paths, ["yolo", "fomo"])
        self.assertEqual(file_category.access_monitoring, False)

    # update file category

    def test_update_file_category_redirect(self):
        file_category = self._force_file_category()
        self._login_redirect(reverse("osquery:update_file_category", args=(file_category.pk,)))

    def test_update_file_category_permission_denied(self):
        file_category = self._force_file_category()
        self._login()
        response = self.client.get(reverse("osquery:update_file_category", args=(file_category.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_file_category_get(self):
        file_category = self._force_file_category()
        self._login("osquery.change_filecategory")
        response = self.client.get(reverse("osquery:update_file_category", args=(file_category.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/filecategory_form.html")
        self.assertContains(response, "Update File category")
        self.assertContains(response, file_category.name)

    def test_update_file_category_post(self):
        file_category = self._force_file_category()
        self._login("osquery.change_filecategory", "osquery.view_filecategory")
        new_name = get_random_string(12)
        response = self.client.post(reverse("osquery:update_file_category", args=(file_category.pk,)),
                                    {"name": new_name,
                                     "file_paths": "yolo, 2020forever",
                                     "access_monitoring": "on"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/filecategory_detail.html")
        self.assertContains(response, new_name)
        file_category = response.context["object"]
        self.assertEqual(file_category.name, new_name)
        self.assertEqual(file_category.file_paths, ["yolo", "2020forever"])
        self.assertEqual(file_category.access_monitoring, True)

    # delete file category

    def test_delete_file_category_redirect(self):
        file_category = self._force_file_category()
        self._login_redirect(reverse("osquery:delete_file_category", args=(file_category.pk,)))

    def test_delete_file_category_permission_denied(self):
        file_category = self._force_file_category()
        self._login()
        response = self.client.get(reverse("osquery:delete_file_category", args=(file_category.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_file_category_get(self):
        file_category = self._force_file_category()
        self._login("osquery.delete_filecategory")
        response = self.client.get(reverse("osquery:delete_file_category", args=(file_category.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/filecategory_confirm_delete.html")
        self.assertContains(response, file_category.name)

    def test_delete_file_category_post(self):
        file_category = self._force_file_category()
        self._login("osquery.delete_filecategory", "osquery.view_filecategory")
        response = self.client.post(reverse("osquery:delete_file_category", args=(file_category.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/filecategory_list.html")
        self.assertEqual(FileCategory.objects.filter(pk=file_category.pk).count(), 0)
        self.assertNotContains(response, file_category.name)

    # file category list

    def test_file_category_list_redirect(self):
        self._login_redirect(reverse("osquery:file_categories"))

    def test_file_category_permission_denied(self):
        self._login()
        response = self.client.get(reverse("osquery:file_categories"))
        self.assertEqual(response.status_code, 403)

    def test_file_category_list(self):
        file_category = self._force_file_category()
        self._login("osquery.view_filecategory")
        response = self.client.get(reverse("osquery:file_categories"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/filecategory_list.html")
        self.assertIn(file_category, response.context["object_list"])
        self.assertContains(response, file_category.name)
