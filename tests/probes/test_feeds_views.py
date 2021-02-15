import json
from unittest.mock import patch, MagicMock
from django.urls import reverse
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
        cls.pwd = "godzillapwd"
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", cls.pwd)

    # utility methods

    def login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    @patch("zentral.core.probes.feeds.fetch_feed")
    def _create_feed(self, fetch_feed):
        fetch_feed.return_value = json.dumps(FEED)
        feed, _ = update_or_create_feed(FEED_URL)
        sync_feed(feed)
        feed_probe = feed.feedprobe_set.all()[0]
        return feed, feed_probe

    def test_feeds(self):
        url = reverse("probes:feeds")
        self.login_redirect(url)
        self.client.force_login(self.user)
        response = self.client.get(url)
        self.assertContains(response, "0 Feeds", status_code=200)

    def test_add_feed_get(self):
        url = reverse("probes:add_feed")
        self.login_redirect(url)
        self.client.force_login(self.user)
        response = self.client.get(url)
        self.assertContains(response, "Add feed", status_code=200)

    @patch("zentral.core.probes.feeds.requests.get")
    def test_add_feed_post_connection_error(self, requests_get):
        requests_get.side_effect = ConnectionError("Boom!")
        url = reverse("probes:add_feed")
        feed_url = "http://dewkjhdkwjhkjedhwdkwj.de/zu"
        response = self.client.post(url, {"url": feed_url}, follow=True)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))
        self.client.force_login(self.user)
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
        self.client.force_login(self.user)
        feed_url = "http://dewkjhdkwjhkjedhwdkwj.de/zu"
        response = self.client.post(reverse("probes:add_feed"),
                                    {"url": feed_url},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/add_feed.html")
        self.assertFormError(response, "form", "url", "HTTP error 404")
        requests_get.assert_called_once_with(feed_url, stream=True)

    @patch("zentral.core.probes.feeds.fetch_feed")
    def test_add_feed_post_feed_error(self, fetch_feed):
        fetch_feed.return_value = "invalid JSON"
        self.client.force_login(self.user)
        feed_url = "http://dewkjhdkwjhkjedhwdkwj.de/zu"
        response = self.client.post(reverse("probes:add_feed"),
                                    {"url": feed_url},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/add_feed.html")
        self.assertFormError(response, "form", "url", "Invalid JSON")
        fetch_feed.assert_called_once_with(feed_url)

    @patch("zentral.core.probes.feeds.fetch_feed")
    def test_add_feed_post_query_pack_ok(self, fetch_feed):
        fetch_feed.return_value = json.dumps(FEED)
        self.client.force_login(self.user)
        response = self.client.post(reverse("probes:add_feed"),
                                    {"url": FEED_URL},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/feed.html")
        self.assertIn("object", response.context)
        feed = response.context["object"]
        self.assertEqual(feed.url, FEED_URL)
        self.assertEqual(feed.name, FEED["name"])

    def test_create_feed_redirect(self):
        url = reverse("probes:add_feed")
        response = self.client.post(url, {"url": FEED_URL}, follow=True)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def test_feed_ok(self):
        feed, _ = self._create_feed()
        self.client.force_login(self.user)
        response = self.client.get(feed.get_absolute_url())
        self.assertContains(response, FEED["name"], status_code=200)

    def test_delete_feed_get(self):
        feed, _ = self._create_feed()
        url = reverse("probes:delete_feed", args=(feed.id,))
        self.login_redirect(url)
        self.client.force_login(self.user)
        response = self.client.get(url)
        self.assertContains(response, "Delete feed", status_code=200)

    def test_delete_feed_post(self):
        feed, _ = self._create_feed()
        url = reverse("probes:delete_feed", args=(feed.id,))
        self.login_redirect(url)
        self.client.force_login(self.user)
        response = self.client.post(url, follow=True)
        self.assertContains(response, "0 Feed", status_code=200)

    def test_sync_feed(self):
        self.client.force_login(self.user)
        feed, _ = self._create_feed()
        url = reverse("probes:sync_feed", args=(feed.id,))
        response = self.client.post(url, follow=True)
        self.assertContains(response, feed.name, status_code=200)
        self.assertTemplateUsed(response, "core/probes/feed.html")
        self.client.logout()
        response = self.client.post(url, follow=True)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def test_feed_probe_ok(self):
        _, feed_probe = self._create_feed()
        self.client.force_login(self.user)
        url = reverse("probes:feed_probe", args=(feed_probe.feed.id, feed_probe.id))
        response = self.client.get(url)
        self.assertContains(response, feed_probe.name, status_code=200)
        self.client.logout()
        self.login_redirect(url)

    def test_feed_probe_import_get(self):
        feed, feed_probe = self._create_feed()
        self.client.force_login(self.user)
        url = reverse("probes:import_feed_probe", args=(feed_probe.feed.id, feed_probe.id))
        response = self.client.get(url)
        self.assertContains(response, "Import feed probe", status_code=200)
        self.client.logout()
        self.login_redirect(url)

    def test_feed_probe_import_post(self):
        feed, feed_probe = self._create_feed()
        url = reverse("probes:import_feed_probe", args=(feed_probe.feed.id, feed_probe.id))
        probe_name = "Godzilla probe"
        response = self.client.post(url, {"probe_name": probe_name},
                                    follow=True)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))
        self.client.force_login(self.user)
        response = self.client.post(url, {"probe_name": probe_name},
                                    follow=True)
        self.assertContains(response, "Probe <em>{}</em>".format(probe_name), status_code=200)
        self.assertContains(response, feed.name)
        self.assertContains(response, feed_probe.name)
