from datetime import datetime
from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from zentral.contrib.inventory.models import MachineSnapshotCommit
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MachineAppsProfilesViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        # machine snapshot
        cls.computer_name = "yolozulu"
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
            "system_info": {"computer_name": cls.computer_name},
            "os_version": {'name': 'OS X', 'major': 10, 'minor': 11, 'patch': 1},
            "android_apps": [
                {"display_name": "AndroidApp1",
                 "version_name": "1.1"},
                {"display_name": "AndroidApp2",
                 "version_name": "1.2"}
            ],
            "deb_packages": [
                {"name": "deb_package_1", "version": "1.1"},
                {"name": "deb_package_2", "version": "1.2"},
            ],
            "ios_apps": [
                {"name": "2Password",
                 "version": "1.1"},
                {"name": "3Password",
                 "version": "1.2"}
            ],
            "osx_app_instances": [
                {'app': {'bundle_id': 'io.zentral.baller',
                         'bundle_name': 'Baller.app',
                         'bundle_version': '123',
                         'bundle_version_str': '1.2.3'},
                 'bundle_path': "/Applications/Baller.app",
                 'signed_by': {
                     "common_name": "Developer ID Application: GODZILLA",
                     "organization": "GOZILLA INC",
                     "organizational_unit": "ATOM",
                     "sha_1": 40 * "a",
                     "sha_256": 64 * "a",
                     "valid_from": datetime(2015, 1, 1),
                     "valid_until": datetime(2026, 1, 1),
                     "signed_by": {
                         "common_name": "Developer ID Certification Authority",
                         "organization": "Apple Inc.",
                         "organizational_unit": "Apple Certification Authority",
                         "sha_1": "3b166c3b7dc4b751c9fe2afab9135641e388e186",
                         "sha_256": "7afc9d01a62f03a2de9637936d4afe68090d2de18d03f29c88cfb0b1ba63587f",
                         "valid_from": datetime(2012, 12, 1),
                         "valid_until": datetime(2027, 12, 1),
                         "signed_by": {
                             "common_name": "Apple Root CA",
                             "organization": "Apple Inc.",
                             "organizational_unit": "Apple Certification Authority",
                             "sha_1": "611e5b662c593a08ff58d14ae22452d198df6c60",
                             "sha_256": "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
                             "valid_from": datetime(2006, 4, 25),
                             "valid_until": datetime(2035, 2, 9)
                         }
                     }
                 }}
            ],
            'profiles': [
                {'display_name': 'Zentral - FileVault configuration',
                 'encrypted': False,
                 'has_removal_passcode': False,
                 'identifier': 'com.zentral.mdm.fv',
                 'payloads': [{'identifier': 'com.zentral.mdm.fv.escrow',
                               'type': 'com.apple.security.FDERecoveryKeyEscrow',
                               'uuid': '6cc2b5a5-d48c-46cf-9f08-59207b9b61f3'},
                              {'identifier': 'com.zentral.mdm.fv.options',
                               'type': 'com.apple.MCX',
                               'uuid': 'dcddb0ec-5429-4148-9054-ad49f12256e7'},
                              {'identifier': 'com.zentral.mdm.fv.configuration',
                               'type': 'com.apple.MCX.FileVault2',
                               'uuid': '3bac4ab2-835b-4786-a538-a36ba8175e32'},
                              {'identifier': 'com.zentral.mdm.fv.certificate',
                               'type': 'com.apple.security.pkcs1',
                               'uuid': '5328b541-893e-4a5d-bb91-84900062fd9f'}],
                 'removal_disallowed': False,
                 'signed_by': {'common_name': 'yolo.example.com',
                               'sha_1': '1111111111111111111111111111111111111111',
                               'signed_by': {'common_name': 'E5',
                                             'organization': "Let's Encrypt",
                                             'sha_1': '5f28d9c589ee4bf31a11b78c72b8d13f079ddc45',
                                             'valid_from': '2024-03-13T00:00:00',
                                             'valid_until': '2027-03-12T23:59:59'},
                               'valid_from': '2024-06-01T13:29:01',
                               'valid_until': '2024-09-01T13:29:00'},
                 'uuid': '0b0d3f67-977d-4d3f-bfc8-0db5fdf6c391',
                 'verified': True}
            ],
            "program_instances": [
                {"program": {"name": "program_1", "version": "1.1"},
                 "install_source": "tests"},
                {"program": {"name": "program_2", "version": "1.2"},
                 "install_source": "tests"},
            ],
        }
        _, cls.ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        cls.osx_app_instance = cls.ms.osx_app_instances.all()[0]
        cls.osx_app = cls.osx_app_instance.app

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

    # Android apps

    def test_machine_android_apps_redirect(self):
        self._login_redirect(reverse("inventory:machine_android_apps", args=(self.ms.serial_number,)))

    def test_machine_android_apps_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:machine_android_apps", args=(self.ms.serial_number,)))
        self.assertEqual(response.status_code, 403)

    def test_machine_android_apps(self):
        self._login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:machine_android_apps", args=(self.ms.serial_number,)))
        self.assertTemplateUsed(response, "inventory/machine_android_apps.html")
        self.assertContains(response, "Android apps", status_code=200)
        self.assertContains(response, "AndroidApp1")
        self.assertContains(response, "AndroidApp2")

    # Deb packages

    def test_machine_deb_packages_redirect(self):
        self._login_redirect(reverse("inventory:machine_deb_packages", args=(self.ms.serial_number,)))

    def test_machine_deb_packages_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:machine_deb_packages", args=(self.ms.serial_number,)))
        self.assertEqual(response.status_code, 403)

    def test_machine_deb_packages(self):
        self._login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:machine_deb_packages", args=(self.ms.serial_number,)))
        self.assertTemplateUsed(response, "inventory/machine_deb_packages.html")
        self.assertContains(response, "Debian packages", status_code=200)
        self.assertContains(response, "deb_package_1")
        self.assertContains(response, "deb_package_2")

    # iOS apps

    def test_machine_ios_apps_redirect(self):
        self._login_redirect(reverse("inventory:machine_ios_apps", args=(self.ms.serial_number,)))

    def test_machine_ios_apps_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:machine_ios_apps", args=(self.ms.serial_number,)))
        self.assertEqual(response.status_code, 403)

    def test_machine_ios_apps(self):
        self._login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:machine_ios_apps", args=(self.ms.serial_number,)))
        self.assertTemplateUsed(response, "inventory/machine_ios_apps.html")
        self.assertContains(response, "iOS apps", status_code=200)
        self.assertContains(response, "2Password")
        self.assertContains(response, "3Password")

    # macOS apps

    def test_machine_macos_app_instances_redirect(self):
        self._login_redirect(reverse("inventory:machine_macos_app_instances", args=(self.ms.serial_number,)))

    def test_machine_macos_app_instances_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:machine_macos_app_instances", args=(self.ms.serial_number,)))
        self.assertEqual(response.status_code, 403)

    def test_machine_macos_app_instances(self):
        self._login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:machine_macos_app_instances", args=(self.ms.serial_number,)))
        self.assertTemplateUsed(response, "inventory/machine_macos_app_instances.html")
        self.assertContains(response, "macOS apps", status_code=200)
        self.assertContains(response, "Baller.app")
        self.assertContains(response, "io.zentral.baller")

    # Profiles

    def test_machine_profiles_redirect(self):
        self._login_redirect(reverse("inventory:machine_profiles", args=(self.ms.serial_number,)))

    def test_machine_profiles_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:machine_profiles", args=(self.ms.serial_number,)))
        self.assertEqual(response.status_code, 403)

    def test_machine_profiles(self):
        self._login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:machine_profiles", args=(self.ms.serial_number,)))
        self.assertTemplateUsed(response, "inventory/machine_profiles.html")
        self.assertContains(response, "Profiles", status_code=200)
        self.assertContains(response, "Zentral - FileVault configuration")

    # Programs

    def test_machine_program_instances_redirect(self):
        self._login_redirect(reverse("inventory:machine_program_instances", args=(self.ms.serial_number,)))

    def test_machine_program_instances_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:machine_program_instances", args=(self.ms.serial_number,)))
        self.assertEqual(response.status_code, 403)

    def test_machine_program_instances(self):
        self._login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:machine_program_instances", args=(self.ms.serial_number,)))
        self.assertTemplateUsed(response, "inventory/machine_program_instances.html")
        self.assertContains(response, "Programs", status_code=200)
        self.assertContains(response, "program_1")
        self.assertContains(response, "program_2")
