from accounts.models import User
from django.contrib.auth.models import Group
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.crypto import get_random_string

from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.inventory.models import MachineSnapshotCommit

from .utils import create_ms


class MachineAppsProfilesViewsTestCase(TestCase, LoginCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        # machine snapshot
        cls.computer_name = "yolozulu"
        cls.ms = create_ms(cls.computer_name)
        cls.osx_app_instance = cls.ms.osx_app_instances.all()[0]
        cls.osx_app = cls.osx_app_instance.app

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "inventory"

    # Android apps

    def test_machine_android_apps_redirect(self):
        self.login_redirect("machine_android_apps", self.ms.serial_number)

    def test_machine_android_apps_permission_denied(self):
        self.login()
        response = self.client.get(reverse("inventory:machine_android_apps", args=(self.ms.serial_number,)))
        self.assertEqual(response.status_code, 403)

    def test_machine_android_apps(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:machine_android_apps", args=(self.ms.serial_number,)))
        self.assertTemplateUsed(response, "inventory/machine_android_apps.html")
        self.assertContains(response, "Android apps", status_code=200)
        self.assertContains(response, "AndroidApp1")
        self.assertContains(response, "AndroidApp2")

    # Deb packages

    def test_machine_deb_packages_redirect(self):
        self.login_redirect("machine_deb_packages", self.ms.serial_number)

    def test_machine_deb_packages_permission_denied(self):
        self.login()
        response = self.client.get(reverse("inventory:machine_deb_packages", args=(self.ms.serial_number,)))
        self.assertEqual(response.status_code, 403)

    def test_machine_deb_packages(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:machine_deb_packages", args=(self.ms.serial_number,)))
        self.assertTemplateUsed(response, "inventory/machine_deb_packages.html")
        self.assertContains(response, "Debian packages", status_code=200)
        self.assertContains(response, "deb_package_1")
        self.assertContains(response, "deb_package_2")

    # iOS apps

    def test_machine_ios_apps_redirect(self):
        self.login_redirect("machine_ios_apps", self.ms.serial_number)

    def test_machine_ios_apps_permission_denied(self):
        self.login()
        response = self.client.get(reverse("inventory:machine_ios_apps", args=(self.ms.serial_number,)))
        self.assertEqual(response.status_code, 403)

    def test_machine_ios_apps(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:machine_ios_apps", args=(self.ms.serial_number,)))
        self.assertTemplateUsed(response, "inventory/machine_ios_apps.html")
        self.assertContains(response, "iOS apps", status_code=200)
        self.assertContains(response, "2Password")
        self.assertContains(response, "3Password")

    # macOS apps

    def test_machine_macos_app_instances_redirect(self):
        self.login_redirect("machine_macos_app_instances", self.ms.serial_number)

    def test_machine_macos_app_instances_permission_denied(self):
        self.login()
        response = self.client.get(reverse("inventory:machine_macos_app_instances", args=(self.ms.serial_number,)))
        self.assertEqual(response.status_code, 403)

    def test_machine_macos_app_instances(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:machine_macos_app_instances", args=(self.ms.serial_number,)))
        self.assertTemplateUsed(response, "inventory/machine_macos_app_instances.html")
        self.assertContains(response, "apps", status_code=200)
        self.assertContains(response, "Baller.app")
        self.assertContains(response, "Baller_path") # executable_path
        self.assertContains(response, "io.zentral.baller")
        # code signing fields
        self.assertContains(response, "ABCDE12345")  # team_id
        self.assertContains(response, "0123456789abcdef0123456789abcdef01234567")  # cd_hash
        # entitlements: modal trigger + content
        self.assertContains(response, "Entitlements")
        self.assertContains(response, "com.apple.security.app-sandbox")

    def _create_ms_with_signed_osx_app_instances(self, serial_number, count):
        source = {"module": "tests.zentral.io", "name": "Zentral Tests"}
        _, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree({
            "source": source,
            "serial_number": serial_number,
            "osx_app_instances": [
                {"app": {"bundle_id": f"io.zentral.app{i}",
                         "bundle_name": f"App{i}.app",
                         "bundle_version_str": "1.0"},
                 "bundle_path": f"/Applications/App{i}.app",
                 "signed_by": {"common_name": "Developer ID Application: GODZILLA",
                               "sha_256": 64 * "a",
                               "signed_by": {"common_name": "Developer ID Certification Authority",
                                             "sha_256": 64 * "b",
                                             "signed_by": {"common_name": "Apple Root CA",
                                                           "sha_256": 64 * "c"}}}}
                for i in range(count)
            ],
        })
        return ms

    def test_machine_macos_app_instances_without_details(self):
        self.login("inventory.view_machinesnapshot")
        _, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree({
            "source": {"module": "tests.zentral.io", "name": "Zentral Tests"},
            "serial_number": "0000000003",
            "osx_app_instances": [
                {"app": {"bundle_id": "io.zentral.bare",
                         "bundle_name": "Bare.app",
                         "bundle_version_str": "1.0"}}
            ],
        })
        response = self.client.get(reverse("inventory:machine_macos_app_instances", args=(ms.serial_number,)))
        self.assertContains(response, "Bare.app", status_code=200)
        # no expandable row, no reveal target (the collapse id only exists for detail rows)
        self.assertNotContains(response, "app-instance-summary app-instance-expandable")
        self.assertNotContains(response, "ai-details-")
        # muted placeholder marks the row as having nothing to reveal
        self.assertContains(response, "app-instance-no-details")

    def test_machine_macos_app_instances_no_n_plus_1(self):
        self.login("inventory.view_machinesnapshot")
        ms_one = self._create_ms_with_signed_osx_app_instances("0000000001", 1)
        ms_many = self._create_ms_with_signed_osx_app_instances("0000000002", 5)
        url_one = reverse("inventory:machine_macos_app_instances", args=(ms_one.serial_number,))
        url_many = reverse("inventory:machine_macos_app_instances", args=(ms_many.serial_number,))
        # warm up the permission/content-type caches so they don't skew the first measured request
        self.client.get(url_one)
        with CaptureQueriesContext(connection) as ctx_one:
            self.assertEqual(self.client.get(url_one).status_code, 200)
        with CaptureQueriesContext(connection) as ctx_many:
            self.assertEqual(self.client.get(url_many).status_code, 200)
        # the certificate chain is select_related, so the query count must not grow with the
        # number of signed app instances
        self.assertEqual(len(ctx_one.captured_queries), len(ctx_many.captured_queries))

    # Profiles

    def test_machine_profiles_redirect(self):
        self.login_redirect("machine_profiles", self.ms.serial_number)

    def test_machine_profiles_permission_denied(self):
        self.login()
        response = self.client.get(reverse("inventory:machine_profiles", args=(self.ms.serial_number,)))
        self.assertEqual(response.status_code, 403)

    def test_machine_profiles(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:machine_profiles", args=(self.ms.serial_number,)))
        self.assertTemplateUsed(response, "inventory/machine_profiles.html")
        self.assertContains(response, "Profiles", status_code=200)
        self.assertContains(response, "Zentral - FileVault configuration")

    # Programs

    def test_machine_program_instances_redirect(self):
        self.login_redirect("machine_program_instances", self.ms.serial_number)

    def test_machine_program_instances_permission_denied(self):
        self.login()
        response = self.client.get(reverse("inventory:machine_program_instances", args=(self.ms.serial_number,)))
        self.assertEqual(response.status_code, 403)

    def test_machine_program_instances(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:machine_program_instances", args=(self.ms.serial_number,)))
        self.assertTemplateUsed(response, "inventory/machine_program_instances.html")
        self.assertContains(response, "Programs", status_code=200)
        self.assertContains(response, "program_1")
        self.assertContains(response, "program_2")
