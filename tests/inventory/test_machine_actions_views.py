from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from accounts.models import User
from zentral.contrib.inventory.models import MetaMachine


class InventoryMachineActionsViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # utility methods

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

    # inventory

    def test_machine_detail_no_perms_no_machine_tags_action(self):
        self._login("inventory.view_machinesnapshot")
        machine = MetaMachine(serial_number=get_random_string(12))
        response = self.client.get(machine.get_absolute_url())
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertNotContains(
            response,
            reverse("inventory:machine_tags", args=(machine.get_urlsafe_serial_number(),))
        )

    def test_machine_detail_perms_machine_tags_action(self):
        self._login(
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
        self._login("inventory.view_machinesnapshot")
        machine = MetaMachine(serial_number=get_random_string(12))
        response = self.client.get(machine.get_absolute_url())
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertNotContains(
            response,
            reverse("inventory:archive_machine", args=(machine.get_urlsafe_serial_number(),))
        )

    def test_machine_detail_perms_archive_machine_action(self):
        self._login("inventory.change_machinesnapshot", "inventory.view_machinesnapshot")
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
