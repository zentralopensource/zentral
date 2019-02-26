from django.urls import reverse
from django.test import TestCase, override_settings
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class FeedViewsTestCase(TestCase):
    OSQUERY_PACK = "https://raw.githubusercontent.com/facebook/osquery/master/packs/osx-attacks.conf"
    OSQUERY_PACK_NAME = "osx-attacks"

    @classmethod
    def setUpTestData(cls):
        # user
        cls.pwd = "godzillapwd"
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", cls.pwd)

    def login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def log_user_in(self):
        response = self.client.post(reverse('login'),
                                    {'username': self.user.username, 'password': self.pwd},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["user"], self.user)

    def log_user_out(self):
        response = self.client.get(reverse('logout'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["user"].is_authenticated, False)

    def test_feeds(self):
        url = reverse("probes:feeds")
        self.login_redirect(url)
        self.log_user_in()
        response = self.client.get(url)
        self.assertContains(response, "0 Feeds", status_code=200)

    def test_add_feed_get(self):
        url = reverse("probes:add_feed")
        self.login_redirect(url)
        self.log_user_in()
        response = self.client.get(url)
        self.assertContains(response, "Add feed", status_code=200)

    def test_add_feed_post_connection_error(self):
        url = reverse("probes:add_feed")
        response = self.client.post(url, {"url": "http://dewkjhdkwjhkjedhwdkwj.de/zu"},
                                    follow=True)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))
        self.log_user_in()
        response = self.client.post(url, {"url": "http://dewkjhdkwjhkjedhwdkwj.de/zu"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/add_feed.html")
        self.assertFormError(response, "form", "url", "Connection error")

    def test_add_feed_post_http_error_404(self):
        self.log_user_in()
        response = self.client.post(reverse("probes:add_feed"),
                                    {"url": "https://github.com/deklqlkjwd"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/add_feed.html")
        self.assertFormError(response, "form", "url", "HTTP error 404")

    def test_add_feed_post_feed_error(self):
        self.log_user_in()
        response = self.client.post(reverse("probes:add_feed"),
                                    {"url": "https://github.com/facebook/osquery"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/add_feed.html")
        self.assertFormError(response, "form", "url", "Invalid JSON")

    def test_add_feed_post_query_pack_ok(self):
        self.log_user_in()
        response = self.client.post(reverse("probes:add_feed"),
                                    {"url": self.OSQUERY_PACK},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/feed.html")
        self.assertIn("object", response.context)
        feed = response.context["object"]
        self.assertEqual(feed.url, self.OSQUERY_PACK)
        self.assertEqual(feed.name, self.OSQUERY_PACK_NAME)

    def test_create_feed_redirect(self):
        url = reverse("probes:add_feed")
        response = self.client.post(url, {"url": self.OSQUERY_PACK}, follow=True)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def _create_feed(self):
        response = self.client.post(reverse("probes:add_feed"),
                                    {"url": self.OSQUERY_PACK},
                                    follow=True)
        feed = response.context["object"]
        feed_probe = feed.feedprobe_set.all()[0]
        return feed, feed_probe

    def test_feed_ok(self):
        self.log_user_in()
        feed, feed_probe = self._create_feed()
        response = self.client.get(feed.get_absolute_url())
        self.assertContains(response, self.OSQUERY_PACK_NAME, status_code=200)

    def test_delete_feed_get(self):
        self.log_user_in()
        feed, feed_probe = self._create_feed()
        self.log_user_out()
        url = reverse("probes:delete_feed", args=(feed.id,))
        self.login_redirect(url)
        self.log_user_in()
        response = self.client.get(url)
        self.assertContains(response, "Delete feed", status_code=200)

    def test_delete_feed_post(self):
        self.log_user_in()
        feed, feed_probe = self._create_feed()
        self.log_user_out()
        url = reverse("probes:delete_feed", args=(feed.id,))
        self.login_redirect(url)
        self.log_user_in()
        response = self.client.post(url, follow=True)
        self.assertContains(response, "0 Feed", status_code=200)

    def test_sync_feed(self):
        self.log_user_in()
        feed, feed_probe = self._create_feed()
        url = reverse("probes:sync_feed", args=(feed.id,))
        response = self.client.post(url, follow=True)
        self.assertContains(response, feed.name, status_code=200)
        self.assertTemplateUsed(response, "core/probes/feed.html")
        self.log_user_out()
        response = self.client.post(url, follow=True)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def test_feed_probe_ok(self):
        self.log_user_in()
        feed, feed_probe = self._create_feed()
        url = reverse("probes:feed_probe", args=(feed_probe.feed.id, feed_probe.id))
        response = self.client.get(url)
        self.assertContains(response, feed_probe.name, status_code=200)
        self.log_user_out()
        self.login_redirect(url)

    def test_feed_probe_import_get(self):
        self.log_user_in()
        feed, feed_probe = self._create_feed()
        url = reverse("probes:import_feed_probe", args=(feed_probe.feed.id, feed_probe.id))
        response = self.client.get(url)
        self.assertContains(response, "Import feed probe", status_code=200)
        self.log_user_out()
        self.login_redirect(url)

    def test_feed_probe_import_post(self):
        self.log_user_in()
        feed, feed_probe = self._create_feed()
        self.log_user_out()
        url = reverse("probes:import_feed_probe", args=(feed_probe.feed.id, feed_probe.id))
        probe_name = "Godzilla probe"
        response = self.client.post(url, {"probe_name": probe_name},
                                    follow=True)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))
        self.log_user_in()
        response = self.client.post(url, {"probe_name": probe_name},
                                    follow=True)
        self.assertContains(response, "Probe <em>{}</em>".format(probe_name), status_code=200)
        self.assertContains(response, feed.name)
        self.assertContains(response, feed_probe.name)
