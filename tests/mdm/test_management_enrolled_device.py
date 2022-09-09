from functools import reduce
import operator
import plistlib
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import CustomCommand
from .utils import force_dep_enrollment_session, force_ota_enrollment_session, force_user_enrollment_session


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class EnrolledDeviceManagementViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    # utiliy methods

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

    # test enrolled devices

    def test_enrolled_devices_redirect(self):
        self._login_redirect(reverse("mdm:enrolled_devices"))

    def test_enrolled_devices_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:enrolled_devices"))
        self.assertEqual(response.status_code, 403)

    def test_enrolled_devices(self):
        session, device_udid, serial_number = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_devices"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_list.html")
        self.assertContains(response, device_udid)
        self.assertContains(response, serial_number)

    # test enrolled device

    def test_enrolled_device_redirect(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login_redirect(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))

    def test_enrolled_device_permission_denied(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login()
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_enrolled_device_no_enrollment_link(self):
        session, device_udid, serial_number = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, device_udid)
        self.assertContains(response, serial_number)
        self.assertContains(response, "1 Enrollment session")
        self.assertContains(response, session.get_enrollment().name)
        self.assertContains(response, session.realm_user.username)
        self.assertNotContains(response, reverse("mdm:user_enrollment", args=(session.get_enrollment().pk,)))

    def test_enrolled_device_enrollment_link(self):
        session, device_udid, serial_number = force_ota_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.view_otaenrollment")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, device_udid)
        self.assertContains(response, serial_number)
        self.assertContains(response, "1 Enrollment session")
        self.assertContains(response, session.get_enrollment().name)
        self.assertContains(response, reverse("mdm:ota_enrollment", args=(session.get_enrollment().pk,)))

    # create custom command

    def test_enrolled_device_no_custom_command_link(self):
        session, _, _ = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertNotContains(
            response,
            reverse("mdm:create_enrolled_device_custom_command", args=(session.enrolled_device.pk,))
        )

    def test_enrolled_device_custom_command_link(self):
        session, _, _ = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(
            response,
            reverse("mdm:create_enrolled_device_custom_command", args=(session.enrolled_device.pk,))
        )

    def test_create_enrolled_device_custom_command_redirect(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login_redirect(reverse("mdm:create_enrolled_device_custom_command", args=(session.enrolled_device.pk,)))

    def test_create_enrolled_device_custom_command_permission_denied(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_custom_command",
                    args=(session.enrolled_device.pk,))
        )
        self.assertEqual(response.status_code, 403)

    def test_create_enrolled_device_custom_command_get(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.add_devicecommand")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_custom_command",
                    args=(session.enrolled_device.pk,))
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_custom_command.html")

    def test_create_enrolled_device_custom_command_invalid_property_list(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_custom_command",
                    args=(session.enrolled_device.pk,)),
            {"command": "YOLO"}
        )
        self.assertFormError(response, "form", "command", "Invalid property list")

    def test_create_enrolled_device_custom_command_not_a_dictionary(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_custom_command",
                    args=(session.enrolled_device.pk,)),
            {"command": '<plist version="1.0"><array></array></plist>'}
        )
        self.assertFormError(response, "form", "command", "Not a dictionary")

    def test_create_enrolled_device_custom_command_missing_or_empty_request_type(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_custom_command",
                    args=(session.enrolled_device.pk,)),
            {"command": "<dict></dict>"}
        )
        self.assertFormError(response, "form", "command", "Missing or empty RequestType")

    def test_create_enrolled_device_custom_command_ok(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_custom_command",
                    args=(session.enrolled_device.pk,)),
            {"command": "<dict>"
                        "<key>RequestType</key>"
                        "<string>InstalledApplicationList</string>"
                        "<key>ManagedAppsOnly</key>"
                        "<false/>"
                        "</dict>"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, "Custom command successfully created")
        command = session.enrolled_device.commands.first()
        self.assertEqual(command.name, "CustomCommand")
        self.assertEqual(
            plistlib.loads(command.kwargs["command"].encode("utf-8")),
            {"RequestType": "InstalledApplicationList",
             "ManagedAppsOnly": False}
        )

    # download custom command result

    def test_download_enrolled_device_command_result_redirect(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        cmd = CustomCommand.create_for_device(
            session.enrolled_device,
            kwargs={"command": plistlib.dumps({"RequestType": "DeviceInformation"}).decode("utf-8")},
            queue=True
        )
        self._login_redirect(reverse("mdm:download_enrolled_device_command_result", args=(cmd.db_command.uuid,)))

    def test_download_enrolled_device_command_result_permission_denied(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        cmd = CustomCommand.create_for_device(
            session.enrolled_device,
            kwargs={"command": plistlib.dumps({"RequestType": "DeviceInformation"}).decode("utf-8")},
            queue=True
        )
        response = self.client.get(reverse("mdm:download_enrolled_device_command_result", args=(cmd.db_command.uuid,)))
        self.assertEqual(response.status_code, 403)

    def test_download_enrolled_device_command_result_no_result_404(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_devicecommand")
        cmd = CustomCommand.create_for_device(
            session.enrolled_device,
            kwargs={"command": plistlib.dumps({"RequestType": "DeviceInformation"}).decode("utf-8")},
            queue=True
        )
        response = self.client.get(reverse("mdm:download_enrolled_device_command_result", args=(cmd.db_command.uuid,)))
        self.assertEqual(response.status_code, 404)

    def test_download_enrolled_device_command_result(self):
        session, device_udid, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_devicecommand")
        cmd = CustomCommand.create_for_device(
            session.enrolled_device,
            kwargs={"command": plistlib.dumps({"RequestType": "DeviceInformation"}).decode("utf-8")},
            queue=True
        )
        # save result
        result = {
            "CommandUUID": "32771F87-6EE3-4347-B1D5-9F5AC5687711",
            "Status": "Acknowledged",
            "UDID": device_udid
        }
        cmd.db_command.result = plistlib.dumps(result)
        cmd.db_command.save()
        response = self.client.get(reverse("mdm:download_enrolled_device_command_result", args=(cmd.db_command.uuid,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/x-plist")
        self.assertEqual(
            response["Content-Disposition"],
            f'attachment; filename="device_command_{cmd.db_command.uuid}-result.plist"'
        )
        self.assertEqual(plistlib.loads(b"".join(response.streaming_content)), result)
