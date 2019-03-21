from datetime import datetime
from django.urls import reverse
from django.utils.http import urlencode
from django.test import TestCase, override_settings
from zentral.contrib.inventory.models import MachineSnapshotCommit
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MacOSAppsViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.pwd = "godzillapwd"
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", cls.pwd)
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
            ]
        }
        _, cls.ms = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        cls.osx_app_instance = cls.ms.osx_app_instances.all()[0]
        cls.osx_app = cls.osx_app_instance.app

    def log_user_in(self):
        self.client.post(reverse('login'), {'username': self.user.username, 'password': self.pwd})

    def test_macos_apps(self):
        self.log_user_in()
        response = self.client.get(reverse("inventory:macos_apps"))
        self.assertContains(response, "1 macOS application")

    def test_macos_apps_sha_256_search(self):
        self.log_user_in()
        # cert signature
        response = self.client.get("{}?{}".format(
            reverse("inventory:macos_apps"),
            urlencode({"sha_256": "7afc9d01a62f03a2de9637936d4afe68090d2de18d03f29c88cfb0b1ba63587f"})
        ))
        self.assertContains(response, "1 macOS application")
        # binary signature
        response = self.client.get("{}?{}".format(
            reverse("inventory:macos_apps"),
            urlencode({"sha_256": 64 * "a"})
        ))
        self.assertContains(response, "1 macOS application")
        # bad sha 256
        response = self.client.get("{}?{}".format(
            reverse("inventory:macos_apps"),
            urlencode({"sha_256": 64 * "z"})
        ))
        self.assertFormError(response, "search_form", "sha_256", "Enter a valid sha256.")
        # another sha 256
        response = self.client.get("{}?{}".format(
            reverse("inventory:macos_apps"),
            urlencode({"sha_256": 64 * "f"})
        ))
        self.assertContains(response, "0 macOS applications")

    def test_macos_apps_source_search(self):
        self.log_user_in()
        response = self.client.get("{}?{}".format(
            reverse("inventory:macos_apps"),
            urlencode({"source": self.ms.source.id})
        ))
        self.assertContains(response, "1 macOS application")

    def test_macos_apps_bundle_name(self):
        self.log_user_in()
        response = self.client.get("{}?{}".format(
            reverse("inventory:macos_apps"),
            urlencode({"bundle_name": "baller"})
        ))
        self.assertContains(response, "1 macOS application")
        response = self.client.get("{}?{}".format(
            reverse("inventory:macos_apps"),
            urlencode({"bundle_name": "yolo"})
        ))
        self.assertContains(response, "0 macOS applications")

    def test_macos_app(self):
        self.log_user_in()
        response = self.client.get(reverse("inventory:macos_app", args=(self.osx_app.id,)))
        self.assertContains(response, "Baller.app 1.2.3")
        self.assertContains(response, "1 application instance")
        self.assertContains(response, self.osx_app_instance.signed_by.sha_256)

    def test_macos_app_instance_machines(self):
        self.log_user_in()
        response = self.client.get(reverse("inventory:macos_app_instance_machines",
                                           args=(self.osx_app.id, self.osx_app_instance.id)),
                                   follow=True)
        self.assertContains(response, "Baller.app 1.2.3")
        self.assertContains(response, "1 Machine")
        self.assertContains(response, self.osx_app_instance.signed_by.sha_256)
        self.assertContains(response, self.computer_name)
