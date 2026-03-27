from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from zentral.contrib.inventory.models import CurrentMachineSnapshot, MachineSnapshotCommit

from accounts.models import User
from tests.zentral_test_utils.login_case import LoginCase


class ArchiveMachineViewTestCase(TestCase, LoginCase):
    @classmethod
    def setUpTestData(cls):
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

    # utility methods

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
        self.login_redirect("archive_machine", "1111")

    def test_get_permission_denied(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:archive_machine", args=("1111",)))
        self.assertEqual(response.status_code, 403)

    def test_get(self):
        self.login("inventory.change_machinesnapshot")
        response = self.client.get(reverse("inventory:archive_machine", args=("1111",)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/archive_machine.html")

    # POST

    def test_post(self):
        self.create_machine_snapshot(serial_number="1111")
        qs = CurrentMachineSnapshot.objects.filter(serial_number="1111")
        self.assertEqual(qs.count(), 1)
        self.login("inventory.change_machinesnapshot",
                   "inventory.view_machinesnapshot",)
        response = self.client.post(reverse("inventory:archive_machine", args=("1111",)),
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_list.html")
        self.assertEqual(qs.count(), 0)
