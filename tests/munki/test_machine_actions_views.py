from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase

from accounts.models import User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.inventory.models import MetaMachine
from zentral.utils.provisioning import provision
from .utils import force_munki_state


class MunkiMachineActionsViewsTestCase(TestCase, LoginCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        # provision the stores
        provision()
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "munki"

    # force machine full sync

    def test_force_machine_full_sync_redirect(self):
        self.login_redirect("force_machine_full_sync", "012345678")

    def test_force_machine_full_sync_permission_denied(self):
        self.login("munki.view_configuration")
        response = self.client.get(reverse("munki:force_machine_full_sync", args=("012345678",)))
        self.assertEqual(response.status_code, 403)

    def test_force_machine_full_sync_not_found(self):
        self.login("munki.change_munkistate")
        response = self.client.get(reverse("munki:force_machine_full_sync", args=("012345678",)))
        self.assertEqual(response.status_code, 404)

    def test_force_machine_full_sync_get(self):
        munki_state = force_munki_state()
        self.login("munki.change_munkistate")
        response = self.client.get(
            reverse("munki:force_machine_full_sync", args=(munki_state.machine_serial_number,))
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/force_machine_full_sync_confirm.html")
        self.assertContains(response, munki_state.machine_serial_number)

    def test_force_machine_full_sync_post(self):
        munki_state = force_munki_state()
        self.assertIsNone(munki_state.force_full_sync_at)
        self.login("munki.change_munkistate", "inventory.view_machinesnapshot")
        response = self.client.post(
            reverse("munki:force_machine_full_sync", args=(munki_state.machine_serial_number,)),
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, munki_state.machine_serial_number)
        self.assertContains(
            response,
            f"Full sync forced during next Munki run for machine {munki_state.machine_serial_number}"
        )
        munki_state.refresh_from_db()
        self.assertIsNotNone(munki_state.force_full_sync_at)

    # inventory

    def test_machine_detail_no_munki_state_disabled_full_sync(self):
        self.login("munki.change_munkistate", "inventory.view_machinesnapshot")
        machine = MetaMachine(serial_number=get_random_string(12))
        response = self.client.get(machine.get_absolute_url())
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(
            response,
            (
                '<a href="'
                + reverse("munki:force_machine_full_sync", args=(machine.get_urlsafe_serial_number(),))
                + '" class="dropdown-item disabled">Force full sync</a>'
            )
        )

    def test_machine_detail_munki_state_full_sync_enabled(self):
        self.login("munki.change_munkistate", "inventory.view_machinesnapshot")
        machine = MetaMachine(serial_number=get_random_string(12))
        force_munki_state(serial_number=machine.serial_number)
        response = self.client.get(machine.get_absolute_url())
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(
            response,
            (
                '<a href="'
                + reverse("munki:force_machine_full_sync", args=(machine.get_urlsafe_serial_number(),))
                + '" class="dropdown-item">Force full sync</a>'
            )
        )

    def test_machine_detail_no_perm_no_full_sync(self):
        self.login("inventory.view_machinesnapshot")
        machine = MetaMachine(serial_number=get_random_string(12))
        force_munki_state(serial_number=machine.serial_number)
        response = self.client.get(machine.get_absolute_url())
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertNotContains(
            response,
            reverse("munki:force_machine_full_sync", args=(machine.get_urlsafe_serial_number(),))
        )
