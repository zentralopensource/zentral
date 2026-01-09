from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from accounts.models import User
from .utils import create_ms


class MachineAppsProfilesViewsTestCase(TestCase):
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
        self.assertContains(response, "apps", status_code=200)
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
