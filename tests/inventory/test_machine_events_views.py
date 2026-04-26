from unittest.mock import patch
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.core.stores.conf import stores
from zentral.utils.provisioning import provision


class MachineEventsViewsTestCase(TestCase, LoginCase):
    @classmethod
    def setUpTestData(cls):
        # provision the stores
        provision()
        stores._load(force=True)
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group] + stores.admin_console_store.events_url_authorized_roles)

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "inventory"

    # machine events

    def test_machine_events_login_redirect(self):
        self.login_redirect("machine_events", "1111")

    def test_machine_events_permission_denied(self):
        self.login("inventory.view_machinetag")
        response = self.client.get(reverse("inventory:machine_events", args=("1111",)))
        self.assertEqual(response.status_code, 403)

    def test_machine_events(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:machine_events", args=("1111",)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_events.html")

    # fetch machine events

    def test_fetch_login_redirect(self):
        self.login_redirect("fetch_machine_events", "1111")

    def test_fetch_permission_denied(self):
        self.login("inventory.view_machinetag")
        response = self.client.get(reverse("inventory:fetch_machine_events", args=("1111",)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.ElasticsearchStore.fetch_machine_events")
    def test_fetch(self, fetch_machine_events):
        fetch_machine_events.return_value = ([], None)
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:fetch_machine_events", args=("1111",)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    # machine events store redirect

    def test_store_redirect_login_redirect(self):
        self.login_redirect("machine_events_store_redirect", "1111")

    def test_store_redirect_permission_denied(self):
        self.login("inventory.view_machinetag")
        response = self.client.get(reverse("inventory:machine_events_store_redirect", args=("1111",)))
        self.assertEqual(response.status_code, 403)

    def test_store_redirect(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:machine_events_store_redirect", args=("1111",)),
                                   {"es": stores.admin_console_store.name})
        self.assertTrue(response.url.startswith("/kibana/"))
