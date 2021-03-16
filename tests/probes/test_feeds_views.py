from functools import reduce
import json
import operator
from unittest.mock import patch, MagicMock
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import User
from requests.exceptions import ConnectionError, HTTPError
from zentral.core.probes.feeds import sync_feed, update_or_create_feed


FEED = {
    "id": "test-feed",
    "name": "Test feed",
    "description": "Test feed description",
    "probes": {
        "zentral-authentication-events": {
            "model": "BaseProbe",
            'name': "Zentral authentication events",
            "body": {
                "filters": {
                    "metadata": [
                        {"event_types": ['zentral_failed_login',
                                         'zentral_failed_verification',
                                         'zentral_login',
                                         'zentral_logout']}
                    ]
                },
                "incident_severity": None
            }
        }
    }
}
FEED_URL = "https://www.example.com/feed.json"


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class FeedViewsTestCase(TestCase):
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

    @patch("zentral.core.probes.feeds.fetch_feed")
    def _create_feed(self, fetch_feed):
        fetch_feed.return_value = FEED
        feed, _ = update_or_create_feed(FEED_URL)
        sync_feed(feed)
        feed_probe = feed.feedprobe_set.all()[0]
        return feed, feed_probe

    # feeds

    def test_feeds_login_redirect(self):
        self._login_redirect(reverse("probes:feeds"))

    def test_feeds_permission_denied(self):
        self._login()
        response = self.client.get(reverse("probes:feeds"))
        self.assertEqual(response.status_code, 403)

    def test_feeds(self):
        self._login("probes.view_feed")
        response = self.client.get(reverse("probes:feeds"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "0 Feeds", status_code=200)

    # add feed

    def test_add_feed_redirect(self):
        self._login_redirect(reverse("probes:add_feed"))

    def test_add_feed_permission_denied(self):
        self._login()
        response = self.client.get(reverse("probes:add_feed"))
        self.assertEqual(response.status_code, 403)

    def test_add_feed_get(self):
        self._login("probes.add_feed")
        response = self.client.get(reverse("probes:add_feed"))
        self.assertContains(response, "Add feed", status_code=200)

    @patch("zentral.core.probes.feeds.requests.get")
    def test_add_feed_post_connection_error(self, requests_get):
        requests_get.side_effect = ConnectionError("Boom!")
        url = reverse("probes:add_feed")
        feed_url = "http://dewkjhdkwjhkjedhwdkwj.de/zu"
        self._login("probes.add_feed")
        response = self.client.post(url, {"url": feed_url}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/add_feed.html")
        self.assertFormError(response, "form", "url", "Connection error")
        requests_get.assert_called_once_with(feed_url, stream=True)

    @patch("zentral.core.probes.feeds.requests.get")
    def test_add_feed_post_http_error_404(self, requests_get):
        error = HTTPError("Boom 404!")
        error.response = MagicMock()
        error.response.status_code = 404
        requests_get.side_effect = error
        feed_url = "http://dewkjhdkwjhkjedhwdkwj.de/zu"
        self._login("probes.add_feed")
        response = self.client.post(reverse("probes:add_feed"),
                                    {"url": feed_url},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/add_feed.html")
        self.assertFormError(response, "form", "url", "HTTP error 404")
        requests_get.assert_called_once_with(feed_url, stream=True)

    @patch("zentral.core.probes.feeds.fetch_feed")
    def test_add_feed_post_feed_error(self, fetch_feed):
        fetch_feed.side_effect = json.decoder.JSONDecodeError("YALA", "", 0)
        feed_url = "http://dewkjhdkwjhkjedhwdkwj.de/zu"
        self._login("probes.add_feed")
        response = self.client.post(reverse("probes:add_feed"),
                                    {"url": feed_url},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/add_feed.html")
        self.assertFormError(response, "form", "url", "Invalid JSON")
        fetch_feed.assert_called_once_with(feed_url)

    @patch("zentral.core.probes.feeds.fetch_feed")
    def test_add_feed_post_query_pack_ok(self, fetch_feed):
        fetch_feed.return_value = FEED
        self._login("probes.add_feed", "probes.view_feed")
        response = self.client.post(reverse("probes:add_feed"),
                                    {"url": FEED_URL},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/feed.html")
        self.assertIn("object", response.context)
        feed = response.context["object"]
        self.assertEqual(feed.url, FEED_URL)
        self.assertEqual(feed.name, FEED["name"])

    # feed

    def test_feed_redirect(self):
        feed, _ = self._create_feed()
        self._login_redirect(feed.get_absolute_url())

    def test_feed_permission_denied(self):
        feed, _ = self._create_feed()
        self._login()
        response = self.client.get(feed.get_absolute_url())
        self.assertEqual(response.status_code, 403)

    def test_feed_ok(self):
        feed, _ = self._create_feed()
        self._login("probes.view_feed")
        response = self.client.get(feed.get_absolute_url())
        self.assertContains(response, FEED["name"], status_code=200)

    # delete feed

    def test_delete_feed_redirect(self):
        feed, _ = self._create_feed()
        self._login_redirect(reverse("probes:delete_feed", args=(feed.id,)))

    def test_delete_feed_permission_denied(self):
        feed, _ = self._create_feed()
        self._login()
        response = self.client.get(reverse("probes:delete_feed", args=(feed.id,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_feed_get(self):
        feed, _ = self._create_feed()
        self._login("probes.delete_feed")
        response = self.client.get(reverse("probes:delete_feed", args=(feed.id,)))
        self.assertContains(response, "Delete feed", status_code=200)

    def test_delete_feed_post(self):
        feed, _ = self._create_feed()
        self._login("probes.delete_feed", "probes.view_feed")
        response = self.client.post(reverse("probes:delete_feed", args=(feed.id,)), follow=True)
        self.assertContains(response, "0 Feed", status_code=200)

    # sync feed

    def test_sync_feed_redirect(self):
        feed, _ = self._create_feed()
        self._login_redirect(reverse("probes:sync_feed", args=(feed.id,)))

    def test_sync_feed_permission_denied(self):
        feed, _ = self._create_feed()
        self._login()
        response = self.client.get(reverse("probes:sync_feed", args=(feed.id,)))
        self.assertEqual(response.status_code, 403)

    def test_sync_feed_post(self):
        feed, _ = self._create_feed()
        self._login("probes.change_feed", "probes.view_feed")
        response = self.client.post(reverse("probes:sync_feed", args=(feed.id,)), follow=True)
        self.assertContains(response, feed.name, status_code=200)
        self.assertTemplateUsed(response, "core/probes/feed.html")

    # feed probe

    def test_feed_probe_redirect(self):
        _, feed_probe = self._create_feed()
        self._login_redirect(reverse("probes:feed_probe", args=(feed_probe.feed.id, feed_probe.id)))

    def test_feed_probe_permission_denied(self):
        _, feed_probe = self._create_feed()
        self._login()
        response = self.client.get(reverse("probes:feed_probe", args=(feed_probe.feed.id, feed_probe.id)))
        self.assertEqual(response.status_code, 403)

    def test_feed_probe(self):
        _, feed_probe = self._create_feed()
        self._login("probes.view_feedprobe")
        response = self.client.get(reverse("probes:feed_probe", args=(feed_probe.feed.id, feed_probe.id)))
        self.assertContains(response, feed_probe.name, status_code=200)

    # feed probe import

    def test_feed_probe_import_redirect(self):
        feed, feed_probe = self._create_feed()
        self._login_redirect(reverse("probes:import_feed_probe", args=(feed_probe.feed.id, feed_probe.id)))

    def test_feed_probe_import_permission_denied(self):
        feed, feed_probe = self._create_feed()
        self._login()
        response = self.client.get(reverse("probes:import_feed_probe", args=(feed_probe.feed.id, feed_probe.id)))
        self.assertEqual(response.status_code, 403)

    def test_feed_probe_import_get(self):
        feed, feed_probe = self._create_feed()
        self._login("probes.view_feedprobe", "probes.add_probesource")
        response = self.client.get(reverse("probes:import_feed_probe", args=(feed_probe.feed.id, feed_probe.id)))
        self.assertContains(response, "Import feed probe", status_code=200)

    def test_feed_probe_import_post(self):
        feed, feed_probe = self._create_feed()
        url = reverse("probes:import_feed_probe", args=(feed_probe.feed.id, feed_probe.id))
        probe_name = "Godzilla probe"
        self._login("probes.view_feedprobe", "probes.add_probesource", "probes.view_probesource")
        response = self.client.post(url, {"probe_name": probe_name},
                                    follow=True)
        self.assertContains(response, "Probe <em>{}</em>".format(probe_name), status_code=200)
        self.assertContains(response, feed.name)
        self.assertContains(response, feed_probe.name)
