from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.conf import settings


class NginxAuthRequestViewTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.pwd = "yo"
        cls.user = User.objects.create_user("yo", "yo@zentral.io", cls.pwd)
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.group2 = Group.objects.create(name=get_random_string(12))
        # force the extra links we need for this test
        cls.extra_links = [
            # external link for all users
            {"anchor_text": "_ELTEST1_",
             "url": "https://eltest1.example.com"},
            # proxied resource for the group members
            {"anchor_text": "_ELTEST2_",
             "url": "/eltest2/un/",
             "authorized_groups": [cls.group.name]},
            # proxied resource for all users
            {"anchor_text": "_ELTEST3_",
             "url": "/eltest3/un/deux/"},
            # proxied resource for the group2 members
            {"anchor_text": "_ELTEST4_",
             "url": "/eltest4/un/deux/trois",
             "authorized_groups": [cls.group2.name]},
        ]
        settings._collection["extra_links"] = cls.extra_links

    # utility method

    def _make_request(self, original_uri, logged_in=False, **headers):
        if logged_in:
            self.client.force_login(self.user)
        kwargs = {"HTTP_X_ORIGINAL_URI": original_uri}
        kwargs.update(headers)
        return self.client.get(reverse("accounts:nginx_auth_request"), **kwargs)

    # tests

    def test_not_extra_link_not_logged_in_401(self):
        response = self._make_request("/godzilla")
        self.assertEqual(response.status_code, 401)

    def test_not_extra_link_not_logged_in_ajax_403(self):
        response = self._make_request("/godzilla", HTTP_X_REQUESTED_WITH="Godzilla")
        self.assertEqual(response.status_code, 401)
        response = self._make_request("/godzilla", HTTP_X_REQUESTED_WITH="XMLHttpRequest")
        self.assertEqual(response.status_code, 403)

    def test_not_extra_link_not_logged_in_accept_json_403(self):
        response = self._make_request("/godzilla", HTTP_ACCEPT="text/html")
        self.assertEqual(response.status_code, 401)
        response = self._make_request("/godzilla", HTTP_ACCEPT="application/json;text/html")
        self.assertEqual(response.status_code, 403)

    def test_not_extra_link_logged_in_200(self):
        response = self._make_request("/godzilla", logged_in=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get("X-Zentral-Username"), self.user.username)
        self.assertEqual(response.get("X-Zentral-Email"), self.user.email)

    def test_extra_link_for_all_not_logged_in_401(self):
        response = self._make_request("/eltest3/un/deux/")
        self.assertEqual(response.status_code, 401)

    def test_extra_link_for_all_logged_in_200(self):
        response = self._make_request("/eltest3/un/deux/", logged_in=True)
        self.assertEqual(response.status_code, 200)

    def test_restricted_extra_link_not_logged_in_401(self):
        response = self._make_request("/eltest2/un/")
        self.assertEqual(response.status_code, 401)

    def test_restricted_extra_link_logged_in_200(self):
        response = self._make_request("/eltest2/un/", logged_in=True)
        self.assertEqual(response.status_code, 200)

    def test_unauthorized_restricted_extra_link_not_logged_in_401(self):
        response = self._make_request("/eltest4/un/deux/trois")
        self.assertEqual(response.status_code, 401)

    def test_unauthorized_restricted_extra_link_logged_in_403(self):
        response = self._make_request("/eltest4/un/deux/trois", logged_in=True)
        self.assertEqual(response.status_code, 403)
