from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.inventory.machine_actions import MachineAction
from zentral.contrib.inventory.models import MetaMachine
from zentral.utils.provisioning import provision


class InventoryMachineActionsViewsTestCase(TestCase, LoginCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        # stores
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
        return "inventory"

    # base model

    def test_machine_action_missing_permission_required(self):
        with self.assertRaises(ImproperlyConfigured) as cm:
            list(MachineAction("12345678910", None).get_permission_required())
        self.assertEqual(cm.exception.args[0], "MachineAction is missing the permission_required attribute.")

    def test_machine_action_permission_required_iterable(self):
        ma = MachineAction("12345678910", None)
        ma.permission_required = ("inventory.view_machinesnapshot", "inventory.view_machinetag")
        self.assertEqual(
            list(ma.get_permission_required()),
            ["inventory.view_machinesnapshot", "inventory.view_machinetag"],
        )

    # inventory

    def test_machine_detail_no_perms_no_machine_tags_action(self):
        self.login("inventory.view_machinesnapshot")
        machine = MetaMachine(serial_number=get_random_string(12))
        response = self.client.get(machine.get_absolute_url())
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertNotContains(
            response,
            reverse("inventory:machine_tags", args=(machine.get_urlsafe_serial_number(),))
        )

    def test_machine_detail_perms_machine_tags_action(self):
        self.login(
            "inventory.view_machinetag",
            "inventory.add_machinetag",
            "inventory.change_machinetag",
            "inventory.delete_machinetag",
            "inventory.add_tag",
            "inventory.view_machinesnapshot"
        )
        machine = MetaMachine(serial_number=get_random_string(12))
        response = self.client.get(machine.get_absolute_url())
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(
            response,
            (
                '<a href="'
                + reverse("inventory:machine_tags", args=(machine.get_urlsafe_serial_number(),))
                + '" class="dropdown-item">Manage tags</a>'
            )
        )

    def test_machine_detail_no_perms_no_archive_machine_action(self):
        self.login("inventory.view_machinesnapshot")
        machine = MetaMachine(serial_number=get_random_string(12))
        response = self.client.get(machine.get_absolute_url())
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertNotContains(
            response,
            reverse("inventory:archive_machine", args=(machine.get_urlsafe_serial_number(),))
        )

    def test_machine_detail_perms_archive_machine_action(self):
        self.login("inventory.change_machinesnapshot", "inventory.view_machinesnapshot")
        machine = MetaMachine(serial_number=get_random_string(12))
        response = self.client.get(machine.get_absolute_url())
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(
            response,
            (
                '<a href="'
                + reverse("inventory:archive_machine", args=(machine.get_urlsafe_serial_number(),))
                + '" class="dropdown-item text-danger">Archive machine</a>'
            )
        )
