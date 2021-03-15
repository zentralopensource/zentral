from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import User
from zentral.contrib.osquery.models import Query


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class OsquerySetupQueriesViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string())
        cls.group = Group.objects.create(name=get_random_string())
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

    def _force_query(self):
        return Query.objects.create(name=get_random_string(), sql="select 1 from processes;")

    # create query

    def test_create_query_redirect(self):
        self._login_redirect(reverse("osquery:create_query"))

    def test_create_query_permission_denied(self):
        self._login()
        response = self.client.get(reverse("osquery:create_query"))
        self.assertEqual(response.status_code, 403)

    def test_create_query_get(self):
        self._login("osquery.add_query")
        response = self.client.get(reverse("osquery:create_query"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/query_form.html")
        self.assertContains(response, "Create Query")

    def test_create_query_post(self):
        self._login("osquery.add_query", "osquery.view_query")
        query_name = get_random_string()
        response = self.client.post(reverse("osquery:create_query"),
                                    {"name": query_name,
                                     "sql": "select 1 from users;",
                                     "description": "YOLO"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/query_detail.html")
        self.assertContains(response, query_name)
        query = response.context["object"]
        self.assertEqual(query.name, query_name)
        self.assertEqual(query.sql, "select 1 from users;")
        self.assertEqual(query.description, "YOLO")

    # update query

    def test_update_query_redirect(self):
        query = self._force_query()
        self._login_redirect(reverse("osquery:update_query", args=(query.pk,)))

    def test_update_query_permission_denied(self):
        query = self._force_query()
        self._login()
        response = self.client.get(reverse("osquery:update_query", args=(query.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_query_get(self):
        query = self._force_query()
        self._login("osquery.change_query")
        response = self.client.get(reverse("osquery:update_query", args=(query.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/query_form.html")

    def test_update_query_post(self):
        query = self._force_query()
        self._login("osquery.change_query", "osquery.view_query")
        new_name = get_random_string()
        response = self.client.post(reverse("osquery:update_query", args=(query.pk,)),
                                    {"name": new_name,
                                     "sql": "select 2 from users;",
                                     "description": "YOLO2"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/query_detail.html")
        self.assertContains(response, new_name)
        query = response.context["object"]
        self.assertEqual(query.name, new_name)
        self.assertEqual(query.sql, "select 2 from users;")
        self.assertEqual(query.description, "YOLO2")

    # delete query

    def test_delete_query_redirect(self):
        query = self._force_query()
        self._login_redirect(reverse("osquery:delete_query", args=(query.pk,)))

    def test_delete_query_permission_denied(self):
        query = self._force_query()
        self._login()
        response = self.client.get(reverse("osquery:delete_query", args=(query.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_query_get(self):
        query = self._force_query()
        self._login("osquery.delete_query")
        response = self.client.get(reverse("osquery:delete_query", args=(query.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/query_confirm_delete.html")
        self.assertContains(response, query.name)

    def test_delete_query_post(self):
        query = self._force_query()
        self._login("osquery.delete_query", "osquery.view_query")
        response = self.client.post(reverse("osquery:delete_query", args=(query.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/query_list.html")
        self.assertEqual(Query.objects.filter(pk=query.pk).count(), 0)
        self.assertNotContains(response, query.name)

    # query list

    def test_query_list_redirect(self):
        self._login_redirect(reverse("osquery:queries"))

    def test_query_list_permission_denied(self):
        self._login()
        response = self.client.get(reverse("osquery:queries"))
        self.assertEqual(response.status_code, 403)

    def test_query_list(self):
        query = self._force_query()
        self._login("osquery.view_query")
        response = self.client.get(reverse("osquery:queries"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/query_list.html")
        self.assertIn(query, response.context["object_list"])
        self.assertContains(response, query.name)
