import copy
from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from zentral.core.incidents.models import Severity
from zentral.core.probes.models import Feed
from zentral.core.probes.feeds import sync_feed
from accounts.models import APIToken, User
from .test_feeds_views import FEED


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class ProbeViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.service_account = User.objects.create_user(
            username="godzilla",
            email="godzilla@zentral.io",
            is_service_account=True
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.api_key = APIToken.objects.update_or_create_for_user(cls.service_account)

    # utility methods

    def set_permissions(self, *permissions):
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

    def put_data(self, url, data, content_type="application/json", include_token=True):
        kwargs = {"content_type": content_type}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.put(url, data, **kwargs)

    def force_feed(self, sync=False):
        feed = Feed.objects.create(name=get_random_string(12))
        if sync:
            sync_feed(feed, FEED)
        return feed

    # put feed

    def test_put_feed_unauthorized(self):
        feed = self.force_feed()
        response = self.put_data(reverse("probes_api:feed", args=(feed.pk,)), FEED, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_put_feed_permission_denied(self):
        feed = self.force_feed()
        self.set_permissions("probes.view_feed")
        response = self.put_data(reverse("probes_api:feed", args=(feed.pk,)), FEED)
        self.assertEqual(response.status_code, 403)

    def test_put_feed(self):
        feed = self.force_feed()
        self.set_permissions("probes.change_feed")
        response = self.put_data(reverse("probes_api:feed", args=(feed.pk,)), FEED)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {'result': 'Probes created: 1.'})
        feed.refresh_from_db()
        self.assertEqual(feed.name, "Test feed")

    def test_put_feed_missing_required_fields_errors(self):
        feed = self.force_feed()
        self.set_permissions("probes.change_feed")
        response = self.put_data(reverse("probes_api:feed", args=(feed.pk,)), {})
        self.assertEqual(response.status_code, 400)
        for field in ("name", "id", "probes"):
            self.assertEqual(response.data[field][0].code, "required")
            self.assertEqual(str(response.data[field][0]), "This field is required.")

    def test_put_feed_unknown_probe_model(self):
        feed = self.force_feed()
        self.set_permissions("probes.change_feed")
        data = copy.deepcopy(FEED)
        data["probes"]["zentral-authentication-events"]["model"] = "yolo"
        response = self.put_data(reverse("probes_api:feed", args=(feed.pk,)), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data,
            {'result': 'Could not sync feed: Probe zentral-authentication-events: unknown model yolo'}
        )

    def test_put_feed_invalid_probe_body(self):
        feed = self.force_feed()
        self.set_permissions("probes.change_feed")
        data = copy.deepcopy(FEED)
        data["probes"]["zentral-authentication-events"]["body"] = "yolo"
        response = self.put_data(reverse("probes_api:feed", args=(feed.pk,)), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data,
            {'result': 'Could not sync feed: Probe zentral-authentication-events: invalid BaseProbe body'}
        )

    def test_put_feed_probe_model_change_error(self):
        feed = self.force_feed(sync=True)
        self.set_permissions("probes.change_feed")
        data = copy.deepcopy(FEED)
        data["probes"]["zentral-authentication-events"]["model"] = "MunkiInstallProbe"
        data["probes"]["zentral-authentication-events"]["body"] = {
            "install_types": ["install"],
            "installed_item_names": ["Firefox"],
            "unattended_installs": True
        }
        response = self.put_data(reverse("probes_api:feed", args=(feed.pk,)), data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data,
            {'result': 'Could not sync feed: Cannot change feed probe test-feed.zentral-authentication-events model'}
        )

    def test_put_feed_probe_model_no_changes(self):
        feed = self.force_feed(sync=True)
        self.set_permissions("probes.change_feed")
        response = self.put_data(reverse("probes_api:feed", args=(feed.pk,)), FEED)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {'result': 'No changes.'})

    def test_put_feed_probe_model_one_update(self):
        feed = self.force_feed(sync=True)
        self.set_permissions("probes.change_feed")
        data = copy.deepcopy(FEED)
        data["probes"]["zentral-authentication-events"]["body"]["incident_severity"] = Severity.CRITICAL.value
        response = self.put_data(reverse("probes_api:feed", args=(feed.pk,)), data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {'result': 'Probes updated: 1.'})
