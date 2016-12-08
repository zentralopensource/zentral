from django.core.urlresolvers import reverse
from django.test import TestCase, override_settings


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class FeedViewsTestCase(TestCase):
    OSQUERY_PACK = "https://raw.githubusercontent.com/facebook/osquery/master/packs/osx-attacks.conf"
    OSQUERY_PACK_NAME = "osx-attacks"

    def test_feeds(self):
        response = self.client.get(reverse("probes:feeds"))
        self.assertContains(response, "0 Feeds", status_code=200)

    def test_add_feed_get(self):
        response = self.client.get(reverse("probes:add_feed"))
        self.assertContains(response, "Add feed", status_code=200)

    def test_add_feed_post_connection_error(self):
        response = self.client.post(reverse("probes:add_feed"),
                                    {"url": "http://dewkjhdkwjhkjedhwdkwj.de/zu"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/add_feed.html")
        self.assertFormError(response, "form", "url", "Connection error")

    def test_add_feed_post_http_error_404(self):
        response = self.client.post(reverse("probes:add_feed"),
                                    {"url": "https://github.com/deklqlkjwd"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/add_feed.html")
        self.assertFormError(response, "form", "url", "HTTP error 404")

    def test_add_feed_post_feed_error(self):
        response = self.client.post(reverse("probes:add_feed"),
                                    {"url": "https://github.com/facebook/osquery"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/add_feed.html")
        self.assertFormError(response, "form", "url", "Invalid JSON")

    def test_add_feed_post_query_pack_ok(self):
        response = self.client.post(reverse("probes:add_feed"),
                                    {"url": self.OSQUERY_PACK},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/feed.html")
        self.assertIn("object", response.context)
        feed = response.context["object"]
        self.assertEqual(feed.url, self.OSQUERY_PACK)
        self.assertEqual(feed.name, self.OSQUERY_PACK_NAME)

    def _create_feed(self):
        response = self.client.post(reverse("probes:add_feed"),
                                    {"url": self.OSQUERY_PACK},
                                    follow=True)
        feed = response.context["object"]
        feed_probe = feed.feedprobe_set.all()[0]
        return feed, feed_probe

    def test_feed_ok(self):
        feed, feed_probe = self._create_feed()
        response = self.client.get(feed.get_absolute_url())
        self.assertContains(response, self.OSQUERY_PACK_NAME, status_code=200)

    def test_delete_feed_get(self):
        feed, feed_probe = self._create_feed()
        response = self.client.get(reverse("probes:delete_feed", args=(feed.id,)))
        self.assertContains(response, "Delete feed", status_code=200)

    def test_delete_feed_post(self):
        feed, feed_probe = self._create_feed()
        response = self.client.post(reverse("probes:delete_feed", args=(feed.id,)),
                                    follow=True)
        self.assertContains(response, "0 Feed", status_code=200)

    def test_sync_feed(self):
        feed, feed_probe = self._create_feed()
        response = self.client.post(reverse("probes:sync_feed", args=(feed.id,)),
                                    follow=True)
        self.assertContains(response, feed.name, status_code=200)
        self.assertTemplateUsed(response, "core/probes/feed.html")

    def test_feed_probe_ok(self):
        feed, feed_probe = self._create_feed()
        response = self.client.get(reverse("probes:feed_probe", args=(feed_probe.feed.id, feed_probe.id)))
        self.assertContains(response, feed_probe.name, status_code=200)

    def test_feed_probe_import_get(self):
        feed, feed_probe = self._create_feed()
        response = self.client.get(reverse("probes:import_feed_probe", args=(feed_probe.feed.id, feed_probe.id)))
        self.assertContains(response, "Import feed probe", status_code=200)

    def test_feed_probe_import_post(self):
        feed, feed_probe = self._create_feed()
        probe_name = "Godzilla probe"
        response = self.client.post(reverse("probes:import_feed_probe", args=(feed_probe.feed.id, feed_probe.id)),
                                    {"probe_name": probe_name},
                                    follow=True)
        self.assertContains(response, "Probe <em>{}</em>".format(probe_name), status_code=200)
        self.assertContains(response, feed.name)
        self.assertContains(response, feed_probe.name)
