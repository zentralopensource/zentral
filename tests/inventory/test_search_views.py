from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.inventory.models import MachineSnapshotCommit, MachineTag, Tag
from zentral.utils.provisioning import provision


class InventorySearchViewsTestCase(TestCase, LoginCase):
    @classmethod
    def setUpTestData(cls):
        provision()  # stores
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        source = {"module": "tests.zentral.io", "name": "Zentral Tests"}
        tree = {
            "source": source,
            "business_unit": {"name": "yo bu",
                              "reference": "bu1",
                              "source": source,
                              "links": [{"anchor_text": "bu link",
                                         "url": "http://bu-link.de"}]},
            "groups": [{"name": "yo grp",
                        "reference": "grp1",
                        "source": source,
                        "links": [{"anchor_text": "group link",
                                   "url": "http://group-link.de"}]}],
            "serial_number": "0123456789",
            "system_info": {"computer_name": "fomo computer name yolo",
                            "hostname": "fomo hostname fomo"},
            "principal_user": {
                "source": {"type": "LOGGED_IN_USER", "properties": {"method": "System Configuration"}},
                "unique_id": "yolo@example.com",
                "principal_name": "Fomo Principal Name Yolo",
                "display_name": "Fomo Display Name Yolo",
            },
            "os_version": {'name': 'OS X', 'major': 10, 'minor': 11, 'patch': 1},
            "osx_app_instances": [
                {'app': {'bundle_id': 'io.zentral.baller',
                         'bundle_name': 'Baller.app',
                         'bundle_version': '123',
                         'bundle_version_str': '1.2.3'},
                 'bundle_path': "/Applications/Baller.app"}
            ],
            "network_interfaces": [
                {'address': '192.168.1.2',
                 'broadcast': '192.168.64.255',
                 'interface': 'en0',
                 'mac': 'b6:21:01:a1:10:a0',
                 'mask': '255.255.255.0'}
            ]
        }
        _, cls.ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        cls.osx_app_instance = cls.ms.osx_app_instances.all()[0]
        cls.tag1 = Tag.objects.create(name="tag1")
        MachineTag.objects.create(tag=cls.tag1, serial_number=cls.ms.serial_number)
        cls.tag2 = Tag.objects.create(name="tag2")

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "inventory"

    # index

    def test_index_login_redirect(self):
        self.login_redirect("index", query_params={"sf": "mbu-t-tp-hm-pf-osv"})

    def test_index_permission_denied(self):
        self.login()
        response = self.client.get(reverse("inventory:index"))
        self.assertEqual(response.status_code, 403)

    def test_index_redirect(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:index"), follow=True)
        self.assertRedirects(response, '?ls=7d&sf=mbu-t-mis-tp-pf-hm-osv')

    def test_index_default(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:index"), {"ls": "7d", "sf": "mbu-t-mis-tp-pf-hm-osv"})
        self.assertTemplateUsed(response, "inventory/machine_list.html")
        self.assertContains(response, "Machine (1)")

    # computer name

    def test_computer_name_search(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(
            reverse("inventory:index"),
            {"ls": "7d", "sf": "mbu-t-mis-tp-pf-hm-osv", "cn": "Computer name Yol"}
        )
        self.assertRedirects(response, reverse("inventory:machine", args=("0123456789",)))

    def test_computer_name_search_special_char_no_result(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(
            reverse("inventory:index"),
            {"ls": "7d", "sf": "mbu-t-mis-tp-pf-hm-osv", "cn": "Computer\\"}
        )
        self.assertTemplateUsed(response, "inventory/machine_list.html")
        self.assertContains(response, "Machines (0)")

    # principal user

    def test_principal_user_principal_name_search(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(
            reverse("inventory:index"),
            {"ls": "7d", "sf": "mbu-t-mis-tp-pf-hm-osv", "pu": "principal name"}
        )
        self.assertRedirects(response, reverse("inventory:machine", args=("0123456789",)))

    def test_principal_user_display_name_search(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(
            reverse("inventory:index"),
            {"ls": "7d", "sf": "mbu-t-mis-tp-pf-hm-osv", "pu": "display name"}
        )
        self.assertRedirects(response, reverse("inventory:machine", args=("0123456789",)))

    def test_principal_user_search_special_char_no_result(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(
            reverse("inventory:index"),
            {"ls": "7d", "sf": "mbu-t-mis-tp-pf-hm-osv", "pu": "Display Name\\"}
        )
        self.assertTemplateUsed(response, "inventory/machine_list.html")
        self.assertContains(response, "Machines (0)")

    # MAC address

    def test_index_mac_address_no_result(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(
            reverse("inventory:index"),
            {"ls": "7d", "sf": "mbu-t-mis-tp-pf-hm-osv", "ma": get_random_string(12)}
        )
        self.assertTemplateUsed(response, "inventory/machine_list.html")
        self.assertContains(response, "Machines (0)")

    def test_index_mac_address_redirect(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(
            reverse("inventory:index"),
            {"ls": "7d", "sf": "mbu-t-mis-tp-pf-hm-osv", "ma": "b6:21:01:a1:10:a0"},
            follow=True
        )
        self.assertRedirects(response, reverse("inventory:machine", args=("0123456789",)))
        self.assertTemplateUsed(response, "inventory/machine_detail.html")

    # bundle filter

    def test_index_add_bundle_filter(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.post(
            "/inventory/?ls=7d&sf=mbu-t-mis-tp-pf-hm-osv",
            {"filter_key": "bundle_filter_form",
             "bf-bundle_id": "org.mozilla.firefoxdeveloperedition"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_list.html")
        self.assertContains(response, "org.mozilla.firefoxdeveloperedition")

    def test_index_add_bundle_filter_error(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.post(
            "/inventory/?ls=7d&sf=mbu-t-mis-tp-pf-hm-osv",
            {"filter_key": "bundle_filter_form"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_list.html")
        self.assertFormError(response.context["bundle_filter_form"], None, "Choose a bundle id or a bundle name.")
