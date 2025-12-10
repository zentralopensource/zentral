from functools import reduce
import operator
from django.apps import apps
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.conf import settings


class BaseViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
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

    # create index

    def test_index_redirect(self):
        self._login_redirect(reverse("base:index"))

    def test_index_get(self):
        self._login()
        response = self.client.get(reverse("base:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "base/index.html")
        self.assertIn(";object-src 'none';", response["Content-Security-Policy"])
        self.assertIn(";script-src 'self' 'nonce-", response["Content-Security-Policy"])
        self.assertNotIn("unsafe-eval", response["Content-Security-Policy"])

    # app histograms

    def test_index_no_perms(self):
        self._login()
        response = self.client.get(reverse("base:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "base/index.html")
        self.assertNotContains(response, 'canvas class="chart"')
        self.assertEqual(len(response.context["apps"]), 0)
        for app_name in apps.app_configs:
            self.assertNotContains(response, 'data-app="{{ app_name }}"')

    def test_index_some_perms(self):
        self._login("compliance_checks.add_compliancecheck", "osquery.view_configuration")
        response = self.client.get(reverse("base:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "base/index.html")
        # No compliance checks because no all events search dict
        self.assertEqual(response.context["apps"], ["osquery"])

    def test_hist_data_unknown_app(self):
        self._login()
        response = self.client.get(reverse("base:app_hist_data", args=("yolo", "day", 14)))
        self.assertEqual(response.status_code, 404)

    def test_hist_data_permission_denied(self):
        self._login("santa.view_configuration")
        for app_name in apps.app_configs:
            response = self.client.get(reverse("base:app_hist_data", args=(app_name, "day", 14)))
            if app_name == "santa":
                self.assertEqual(response.status_code, 200)
            elif response.status_code != 404:
                self.assertEqual(response.status_code, 403)

    def test_index_santa_perms(self):
        self._login("santa.view_configuration", "osquery.view_enrollment")
        response = self.client.get(reverse("base:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "base/index.html")
        self.assertContains(response, 'canvas class="chart"')
        self.assertContains(response, 'data-app="osquery"')
        self.assertContains(response, 'data-app="santa"')
        for app_name in apps.app_configs:
            if app_name in ("osquery", "santa"):
                continue
            self.assertNotContains(response, 'data-app="{{ app_name }}"')

    # extra links

    def test_index_not_logged_in_no_extra_links(self):
        response = self.client.get(reverse("base:index"), follow=True)
        self.assertNotIn("zentral_extra_links", response.context)
        self.assertNotContains(response, "_ELTEST1_")
        self.assertNotContains(response, "https://eltest1.example.com")
        self.assertNotContains(response, "_ELTEST2_")
        self.assertNotContains(response, "/eltest2/un/")
        self.assertNotContains(response, "_ELTEST3_")
        self.assertNotContains(response, "/eltest3/un/deux/")
        self.assertNotContains(response, "_ELTEST4_")
        self.assertNotContains(response, "/eltest4/un/deux/trois")

    def test_index_users_extra_links(self):
        self._login()
        response = self.client.get(reverse("base:index"))
        filtered_links = [link for link in self.extra_links
                          if not link.get("authorized_groups") or self.group.name in link["authorized_groups"]]
        self.assertEqual(response.context["zentral_extra_links"], filtered_links)
        self.assertContains(response, "_ELTEST1_")
        self.assertContains(response, "https://eltest1.example.com")
        self.assertContains(response, "_ELTEST2_")
        self.assertContains(response, "/eltest2/un/")
        self.assertContains(response, "_ELTEST3_")
        self.assertContains(response, "/eltest3/un/deux/")
        self.assertNotContains(response, "_ELTEST4_")
        self.assertNotContains(response, "/eltest4/un/deux/trois")

    def test_index_users_all_extra_links(self):
        self._login()
        self.user.groups.add(self.group2)
        response = self.client.get(reverse("base:index"))
        self.assertEqual(response.context["zentral_extra_links"], self.extra_links)
        self.assertContains(response, "_ELTEST1_")
        self.assertContains(response, "https://eltest1.example.com")
        self.assertContains(response, "_ELTEST2_")
        self.assertContains(response, "/eltest2/un/")
        self.assertContains(response, "_ELTEST3_")
        self.assertContains(response, "/eltest3/un/deux/")
        self.assertContains(response, "_ELTEST4_")
        self.assertContains(response, "/eltest4/un/deux/trois")
