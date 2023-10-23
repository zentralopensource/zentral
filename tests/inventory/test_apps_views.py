from datetime import datetime
from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.http import urlencode
from django.test import TestCase, override_settings
from zentral.contrib.inventory.models import MachineSnapshotCommit
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class AppsViewsTestCase(TestCase):
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
                 }},
                {'app': {'bundle_id': 'io.zentral.kartoffel',
                         'bundle_version': '1234',
                         'bundle_version_str': '1.2.3.4'},
                 'bundle_path': "/Applications/Kartoffel.app",
                 },
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

    def test_android_apps_redirect(self):
        self._login_redirect(reverse("inventory:android_apps"))

    def test_android_apps_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:android_apps"))
        self.assertEqual(response.status_code, 403)

    def test_android_apps(self):
        self._login("inventory.view_androidapp")
        response = self.client.get(reverse("inventory:android_apps"))
        self.assertContains(response, "Android apps", status_code=200)

    def test_all_android_apps(self):
        self._login("inventory.view_androidapp")
        response = self.client.get("{}?{}".format(
            reverse("inventory:android_apps"),
            urlencode({"action": "search"})
        ))
        self.assertContains(response, "Results (2)")

    def test_android_apps_bundle_name(self):
        self._login("inventory.view_androidapp")
        response = self.client.get("{}?{}".format(
            reverse("inventory:android_apps"),
            urlencode({"display_name": "AndroidApp1",
                       "action": "search"})
        ))
        self.assertContains(response, "Result (1)")
        self.assertContains(response, ">AndroidApp1</a>")
        response = self.client.get("{}?{}".format(
            reverse("inventory:android_apps"),
            urlencode({"display_name": "AndroidApp11",
                       "action": "search"})
        ))
        self.assertContains(response, "We didn't find any item related to your search")

    def test_android_apps_bundle_name_and_source_search(self):
        self._login("inventory.view_androidapp")
        response = self.client.get("{}?{}".format(
            reverse("inventory:android_apps"),
            urlencode({"display_name": "AndroidApp1",
                       "source": self.ms.source.id,
                       "action": "search"})
        ))
        self.assertContains(response, "Result (1)")
        self.assertContains(response, ">AndroidApp1</a>")

    # Debian packages

    def test_deb_packages_redirect(self):
        self._login_redirect(reverse("inventory:deb_packages"))

    def test_deb_packages_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:deb_packages"))
        self.assertEqual(response.status_code, 403)

    def test_deb_packages(self):
        self._login("inventory.view_debpackage")
        response = self.client.get(reverse("inventory:deb_packages"))
        self.assertContains(response, "Debian packages", status_code=200)

    def test_all_deb_packages(self):
        self._login("inventory.view_debpackage")
        response = self.client.get("{}?{}".format(
            reverse("inventory:deb_packages"),
            urlencode({"action": "search"})
        ))
        self.assertContains(response, "Results (2)")

    def test_deb_packages_name(self):
        self._login("inventory.view_debpackage")
        response = self.client.get("{}?{}".format(
            reverse("inventory:deb_packages"),
            urlencode({"name": "deb_package_1",
                       "action": "search"})
        ))
        self.assertContains(response, "Result (1)")
        response = self.client.get("{}?{}".format(
            reverse("inventory:deb_packages"),
            urlencode({"name": "deb_package_11",
                       "action": "search"})
        ))
        self.assertContains(response, "We didn't find any item related to your search")

    def test_deb_packages_name_and_source_search(self):
        self._login("inventory.view_debpackage")
        response = self.client.get("{}?{}".format(
            reverse("inventory:deb_packages"),
            urlencode({"name": "deb_package_1",
                       "source": self.ms.source.id,
                       "action": "search"})
        ))
        self.assertContains(response, "Result (1)")

    # iOS apps

    def test_ios_apps_redirect(self):
        self._login_redirect(reverse("inventory:ios_apps"))

    def test_ios_apps_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:ios_apps"))
        self.assertEqual(response.status_code, 403)

    def test_ios_apps(self):
        self._login("inventory.view_iosapp")
        response = self.client.get(reverse("inventory:ios_apps"))
        self.assertContains(response, "iOS apps", status_code=200)

    def test_all_ios_apps(self):
        self._login("inventory.view_iosapp")
        response = self.client.get("{}?{}".format(
            reverse("inventory:ios_apps"),
            urlencode({"action": "search"})
        ))
        self.assertContains(response, "Results (2)")

    def test_ios_apps_name(self):
        self._login("inventory.view_iosapp")
        response = self.client.get("{}?{}".format(
            reverse("inventory:ios_apps"),
            urlencode({"name": "2Password",
                       "action": "search"})
        ))
        self.assertContains(response, "Result (1)")
        response = self.client.get("{}?{}".format(
            reverse("inventory:ios_apps"),
            urlencode({"name": "42Password",
                       "action": "search"})
        ))
        self.assertContains(response, "We didn't find any item related to your search")

    def test_ios_apps_name_and_source_search(self):
        self._login("inventory.view_iosapp")
        response = self.client.get("{}?{}".format(
            reverse("inventory:ios_apps"),
            urlencode({"name": "2Password",
                       "source": self.ms.source.id,
                       "action": "search"})
        ))
        self.assertContains(response, "Result (1)")

    # macOS apps

    def test_macos_apps_redirect(self):
        self._login_redirect(reverse("inventory:macos_apps"))

    def test_macos_apps_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:macos_apps"))
        self.assertEqual(response.status_code, 403)

    def test_macos_apps(self):
        self._login("inventory.view_osxapp", "inventory.view_osxappinstance")
        response = self.client.get(reverse("inventory:macos_apps"))
        self.assertContains(response, "macOS apps", status_code=200)

    def test_all_macos_apps(self):
        self._login("inventory.view_osxapp", "inventory.view_osxappinstance")
        response = self.client.get("{}?{}".format(
            reverse("inventory:macos_apps"),
            urlencode({"action": "search"})
        ))
        self.assertContains(response, "Results (2)")

    def test_macos_apps_bundle_name(self):
        self._login("inventory.view_osxapp", "inventory.view_osxappinstance")
        response = self.client.get("{}?{}".format(
            reverse("inventory:macos_apps"),
            urlencode({"bundle": "baller",
                       "action": "search"})
        ))
        self.assertContains(response, "Result (1)")
        response = self.client.get("{}?{}".format(
            reverse("inventory:macos_apps"),
            urlencode({"bundle": "yolo",
                       "action": "search"})
        ))
        self.assertContains(response, "We didn't find any item related to your search")

    def test_macos_apps_bundle_id_and_source_search(self):
        self._login("inventory.view_osxapp", "inventory.view_osxappinstance")
        response = self.client.get("{}?{}".format(
            reverse("inventory:macos_apps"),
            urlencode({"bundle": "io.zentral.baller",
                       "source": self.ms.source.id,
                       "action": "search"})
        ))
        self.assertContains(response, "Result (1)")

    # Programs

    def test_programs_redirect(self):
        self._login_redirect(reverse("inventory:programs"))

    def test_programs_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:programs"))
        self.assertEqual(response.status_code, 403)

    def test_programs(self):
        self._login("inventory.view_program", "inventory.view_programinstance")
        response = self.client.get(reverse("inventory:programs"))
        self.assertContains(response, "Programs", status_code=200)

    def test_all_programs(self):
        self._login("inventory.view_program", "inventory.view_programinstance")
        response = self.client.get("{}?{}".format(
            reverse("inventory:programs"),
            urlencode({"action": "search"})
        ))
        self.assertContains(response, "Results (2)")

    def test_programs_name(self):
        self._login("inventory.view_program", "inventory.view_programinstance")
        response = self.client.get("{}?{}".format(
            reverse("inventory:programs"),
            urlencode({"name": "program_1",
                       "action": "search"})
        ))
        self.assertContains(response, "Result (1)")
        response = self.client.get("{}?{}".format(
            reverse("inventory:programs"),
            urlencode({"name": "program_11",
                       "action": "search"})
        ))
        self.assertContains(response, "We didn't find any item related to your search")

    def test_programs_name_and_source_search(self):
        self._login("inventory.view_program", "inventory.view_programinstance")
        response = self.client.get("{}?{}".format(
            reverse("inventory:programs"),
            urlencode({"name": "program_1",
                       "source": self.ms.source.id,
                       "action": "search"})
        ))
        self.assertContains(response, "Result (1)")
