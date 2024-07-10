from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import User
from zentral.core.stores.conf import frontend_store


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MachineEventsViewsTestCase(TestCase):
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

    # machine events

    def test_machine_events_login_redirect(self):
        self._login_redirect(reverse("inventory:machine_events", args=("1111",)))

    def test_machine_events_permission_denied(self):
        self._login("inventory.view_machinetag")
        response = self.client.get(reverse("inventory:machine_events", args=("1111",)))
        self.assertEqual(response.status_code, 403)

    def test_machine_events(self):
        self._login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:machine_events", args=("1111",)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_events.html")

    # fetch machine events

    def test_fetch_login_redirect(self):
        self._login_redirect(reverse("inventory:fetch_machine_events", args=("1111",)))

    def test_fetch_permission_denied(self):
        self._login("inventory.view_machinetag")
        response = self.client.get(reverse("inventory:fetch_machine_events", args=("1111",)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.fetch_machine_events")
    def test_fetch(self, fetch_machine_events):
        fetch_machine_events.return_value = ([], None)
        self._login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:fetch_machine_events", args=("1111",)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    # machine events store redirect

    def test_store_redirect_login_redirect(self):
        self._login_redirect(reverse("inventory:machine_events_store_redirect", args=("1111",)))

    def test_store_redirect_permission_denied(self):
        self._login("inventory.view_machinetag")
        response = self.client.get(reverse("inventory:machine_events_store_redirect", args=("1111",)))
        self.assertEqual(response.status_code, 403)

    def test_store_redirect(self):
        self._login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:machine_events_store_redirect", args=("1111",)),
                                   {"es": frontend_store.name})
        self.assertTrue(response.url.startswith("/kibana/"))
