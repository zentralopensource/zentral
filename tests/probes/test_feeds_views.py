from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import User
from zentral.core.probes.feeds import sync_feed
from zentral.core.probes.models import Feed


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


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class FeedViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
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

    def _create_feed(self):
        feed = Feed.objects.create(name=get_random_string(12))
        sync_feed(feed, FEED)
        return feed, feed.feedprobe_set.first()

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

    # create feed

    def test_create_feed_redirect(self):
        self._login_redirect(reverse("probes:create_feed"))

    def test_create_feed_permission_denied(self):
        self._login()
        response = self.client.get(reverse("probes:create_feed"))
        self.assertEqual(response.status_code, 403)

    def test_create_feed_get(self):
        self._login("probes.add_feed")
        response = self.client.get(reverse("probes:create_feed"))
        self.assertContains(response, "Create feed", status_code=200)

    def test_create_feed_error(self):
        self._login("probes.add_feed")
        response = self.client.post(reverse("probes:create_feed"), {}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/feed_form.html")
        self.assertFormError(response, "form", "name", "This field is required.")

    def test_create_feed_post(self):
        self._login("probes.add_feed", "probes.view_feed")
        name = get_random_string(24)
        response = self.client.post(reverse("probes:create_feed"), {"name": name}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/feed.html")
        self.assertContains(response, name)
        self.assertContains(response, "0 Probes")

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

    # update feed

    def test_update_feed_redirect(self):
        feed, _ = self._create_feed()
        self._login_redirect(reverse("probes:update_feed", args=(feed.id,)))

    def test_update_feed_permission_denied(self):
        feed, _ = self._create_feed()
        self._login()
        response = self.client.get(reverse("probes:update_feed", args=(feed.id,)))
        self.assertEqual(response.status_code, 403)

    def test_update_feed_get(self):
        feed, _ = self._create_feed()
        self._login("probes.change_feed")
        response = self.client.get(reverse("probes:update_feed", args=(feed.id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/feed_form.html")
        self.assertContains(response, "Update feed")

    def test_update_feed(self):
        feed, _ = self._create_feed()
        self._login("probes.change_feed", "probes.view_feed")
        new_name = get_random_string(12)
        self.assertNotEqual(feed.name, new_name)
        response = self.client.post(reverse("probes:update_feed", args=(feed.id,)), {"name": new_name}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/feed.html")
        self.assertContains(response, new_name)

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
