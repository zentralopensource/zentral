from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from zentral.contrib.inventory.models import CurrentMachineSnapshot, MachineSnapshotCommit
from accounts.models import User


class ArchiveMachineViewTestCase(TestCase):
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

    def create_machine_snapshot(self, serial_number="1111"):
        source = {"module": "tests.zentral.com", "name": "Zentral Tests"}
        MachineSnapshotCommit.objects.commit_machine_snapshot_tree({
            "source": source,
            "business_unit": {"name": "yolo",
                              "reference": "fomo",
                              "source": source},
            "serial_number": serial_number,
        })

    # GET

    def test_get_login_redirect(self):
        self._login_redirect(reverse("inventory:archive_machine", args=("1111",)))

    def test_get_permission_denied(self):
        self._login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:archive_machine", args=("1111",)))
        self.assertEqual(response.status_code, 403)

    def test_get(self):
        self._login("inventory.change_machinesnapshot")
        response = self.client.get(reverse("inventory:archive_machine", args=("1111",)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/archive_machine.html")

    # POST

    def test_post(self):
        self.create_machine_snapshot(serial_number="1111")
        qs = CurrentMachineSnapshot.objects.filter(serial_number="1111")
        self.assertEqual(qs.count(), 1)
        self._login("inventory.change_machinesnapshot",
                    "inventory.view_machinesnapshot",)
        response = self.client.post(reverse("inventory:archive_machine", args=("1111",)),
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_list.html")
        self.assertEqual(qs.count(), 0)
