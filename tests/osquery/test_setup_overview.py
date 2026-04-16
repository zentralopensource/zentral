from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase

from accounts.models import User
from tests.zentral_test_utils.login_case import LoginCase


class OsquerySetupViewsTestCase(TestCase, LoginCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "osquery"

    # index

    def test_index_redirect(self):
        self.login_redirect("index")

    def test_index_permission_denied(self):
        self.login()
        response = self.client.get(reverse("osquery:index"))
        self.assertEqual(response.status_code, 403)

    def test_index(self):
        self.login("osquery.view_configuration")
        response = self.client.get(reverse("osquery:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/index.html")
