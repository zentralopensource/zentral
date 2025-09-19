from functools import reduce
import operator
import plistlib
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import CustomCommand
from zentral.contrib.mdm.commands.base import load_command
from zentral.contrib.mdm.models import Blueprint, DeviceArtifact, Platform, TargetArtifact
from .utils import (force_artifact, force_blueprint, force_blueprint_artifact,
                    force_dep_enrollment_session, force_ota_enrollment_session, force_user_enrollment_session)


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

    @patch("zentral.contrib.mdm.views.management.EnrolledDeviceListView.get_paginate_by")
    def test_enrolled_devices(self, get_paginate_by):
        get_paginate_by.return_value = 1
        devices = [(t[1], t[2]) for t in (force_dep_enrollment_session(self.mbu, completed=True) for _ in range(3))]
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_devices"), {"page": 2})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_list.html")
        self.assertNotContains(response, '<li class="active">Search</li>')
        self.assertContains(response, "Devices (3)")
        self.assertContains(response, "page 2 of 3")
        for idx, (udid, serial_number) in enumerate(devices):
            if idx != 1:
                self.assertNotContains(response, udid)
                self.assertNotContains(response, serial_number)
            else:
                self.assertContains(response, udid)
                self.assertContains(response, serial_number)

    def test_enrolled_devices_search(self):
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_devices"),)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_list.html")
        self.assertNotContains(response, "We didn't find any item related to your search")
        session, _, serial_number = force_dep_enrollment_session(self.mbu, completed=True)
        enrolled_device = session.enrolled_device
        blueprint = force_blueprint()
        enrolled_device.blueprint = blueprint
        enrolled_device.save()
        response = self.client.get(reverse("mdm:enrolled_devices"), {"q": "does not exists"})
        self.assertTemplateUsed(response, "mdm/enrolleddevice_list.html")
        self.assertContains(response, "We didn't find any item related to your search")
        self.assertContains(response, reverse("mdm:enrolled_devices") + '">all the items')

    def test_enrolled_devices_serial_number_search_redirect(self):
        session, _, serial_number = force_dep_enrollment_session(self.mbu, completed=True)
        enrolled_device = session.enrolled_device
        blueprint = force_blueprint()
        enrolled_device.blueprint = blueprint
        enrolled_device.save()
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(
            reverse("mdm:enrolled_devices"),
            {"q": serial_number[1:-1],
             "platform": "macOS",
             "blueprint": blueprint.pk},
            follow=True
        )
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertEqual(response.context["object"], enrolled_device)

    def test_enrolled_devices_udid_search_redirect(self):
        session, udid, _ = force_dep_enrollment_session(self.mbu, completed=True)
        enrolled_device = session.enrolled_device
        blueprint = force_blueprint()
        enrolled_device.blueprint = blueprint
        enrolled_device.save()
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(
            reverse("mdm:enrolled_devices"),
            {"q": udid[1:-1],
             "platform": "macOS",
             "blueprint": blueprint.pk},
            follow=True
        )
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertEqual(response.context["object"], enrolled_device)

    def test_enrolled_devices_blueprint_search(self):
        session1, _, serial_number1 = force_dep_enrollment_session(self.mbu, completed=True)
        session2, _, serial_number2 = force_dep_enrollment_session(self.mbu, completed=True)
        _, _, serial_number3 = force_dep_enrollment_session(self.mbu, completed=True)
        blueprint = force_blueprint()
        session1.enrolled_device.blueprint = blueprint
        session1.enrolled_device.save()
        session2.enrolled_device.blueprint = blueprint
        session2.enrolled_device.save()
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_devices"), {"blueprint": blueprint.pk})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<li class="breadcrumb-item active">Search</li>')
        self.assertTemplateUsed(response, "mdm/enrolleddevice_list.html")
        self.assertContains(response, "Devices (2)")
        self.assertContains(response, "page 1 of 1")
        self.assertContains(response, serial_number1)
        self.assertContains(response, serial_number2)
        self.assertNotContains(response, serial_number3)

    def test_enrolled_devices_artifact_search(self):
        session1, _, serial_number1 = force_dep_enrollment_session(self.mbu, completed=True)
        session2, _, serial_number2 = force_dep_enrollment_session(self.mbu, completed=True)
        _, _, serial_number3 = force_dep_enrollment_session(self.mbu, completed=True)
        _, artifact, (av,) = force_blueprint_artifact()
        DeviceArtifact.objects.create(enrolled_device=session1.enrolled_device, artifact_version=av, status="Failed")
        DeviceArtifact.objects.create(enrolled_device=session2.enrolled_device, artifact_version=av, status="Failed")
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_devices"), {"artifact": f"a_{artifact.pk}"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "page 1 of 1")
        self.assertContains(response, serial_number1)
        self.assertContains(response, serial_number2)
        self.assertNotContains(response, serial_number3)

    def test_enrolled_devices_artifact_version_search(self):
        session1, _, serial_number1 = force_dep_enrollment_session(self.mbu, completed=True)
        session2, _, serial_number2 = force_dep_enrollment_session(self.mbu, completed=True)
        session3, _, serial_number3 = force_dep_enrollment_session(self.mbu, completed=True)
        _, artifact, (av1, av2) = force_blueprint_artifact(version_count=2)
        DeviceArtifact.objects.create(enrolled_device=session1.enrolled_device, artifact_version=av1, status="Failed")
        DeviceArtifact.objects.create(enrolled_device=session2.enrolled_device, artifact_version=av1, status="Failed")
        DeviceArtifact.objects.create(enrolled_device=session3.enrolled_device, artifact_version=av2, status="Failed")
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_devices"), {"artifact": f"av_{av1.pk}"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "page 1 of 1")
        self.assertContains(response, serial_number1)
        self.assertContains(response, serial_number2)
        self.assertNotContains(response, serial_number3)

    def test_enrolled_devices_artifact_status_search(self):
        session1, _, serial_number1 = force_dep_enrollment_session(self.mbu, completed=True)
        session2, _, serial_number2 = force_dep_enrollment_session(self.mbu, completed=True)
        session3, _, serial_number3 = force_dep_enrollment_session(self.mbu, completed=True)
        _, artifact, (av1, av2) = force_blueprint_artifact(version_count=2)
        DeviceArtifact.objects.create(enrolled_device=session1.enrolled_device, artifact_version=av1, status="Failed")
        DeviceArtifact.objects.create(enrolled_device=session2.enrolled_device, artifact_version=av1, status="Failed")
        DeviceArtifact.objects.create(enrolled_device=session3.enrolled_device, artifact_version=av2,
                                      status="Installed")
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_devices"), {"artifact_status": "Failed"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "page 1 of 1")
        self.assertContains(response, serial_number1)
        self.assertContains(response, serial_number2)
        self.assertNotContains(response, serial_number3)

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
        self.assertContains(response, "Enrollment session (1)")
        self.assertContains(response, session.get_enrollment().name)
        self.assertContains(response, session.realm_user.username)
        self.assertNotContains(response, session.realm_user.get_absolute_url())
        self.assertNotContains(response, reverse("mdm:user_enrollment", args=(session.get_enrollment().pk,)))
        self.assertEqual(response.context["commands_count"], 0)
        self.assertNotContains(response, "See all commands")

    def test_enrolled_device_enrollment_link(self):
        session, device_udid, serial_number = force_ota_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.view_otaenrollment")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, device_udid)
        self.assertContains(response, serial_number)
        self.assertContains(response, "Enrollment session (1)")
        self.assertContains(response, session.get_enrollment().name)
        self.assertContains(response, reverse("mdm:ota_enrollment", args=(session.get_enrollment().pk,)))

    def test_enrolled_device_realm_user_link(self):
        session, device_udid, serial_number = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "realms.view_realmuser")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, session.realm_user.get_absolute_url())

    def test_enrolled_device_no_block_link(self):
        session, device_udid, serial_number = force_ota_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, reverse("mdm:block_enrolled_device", args=(session.enrolled_device.pk,)))

    def test_enrolled_device_block_link(self):
        session, device_udid, serial_number = force_ota_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.change_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("mdm:block_enrolled_device", args=(session.enrolled_device.pk,)))

    def test_enrolled_device_no_unblock_link(self):
        session, device_udid, serial_number = force_ota_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.block()
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, reverse("mdm:unblock_enrolled_device", args=(session.enrolled_device.pk,)))

    def test_enrolled_device_unblock_link(self):
        session, device_udid, serial_number = force_ota_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.block()
        self._login("mdm.view_enrolleddevice", "mdm.change_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("mdm:unblock_enrolled_device", args=(session.enrolled_device.pk,)))

    def test_enrolled_device_pending_firmware_password_change(self):
        session, _, _ = force_ota_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.set_recovery_password("12345678")
        session.enrolled_device.set_pending_firmware_password("")
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice", "mdm.change_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Firmware password")
        self.assertContains(response, "Pending change")

    def test_enrolled_device_one_command(self):
        session, device_udid, serial_number = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        CustomCommand.create_for_device(
            session.enrolled_device,
            kwargs={"command": plistlib.dumps({"RequestType": "DeviceInformation"}).decode("utf-8")},
            queue=True
        )
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, "CustomCommand (DeviceInformation)")
        self.assertEqual(response.context["commands_count"], 1)
        self.assertEqual(len(response.context["loaded_commands"]), 1)
        self.assertNotContains(response, "See all commands")

    def test_enrolled_device_top_10_command(self):
        session, device_udid, serial_number = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        first_command = second_command = None
        for i in range(11):
            cmd = CustomCommand.create_for_device(
                session.enrolled_device,
                kwargs={"command": plistlib.dumps({"RequestType": "DeviceInformation"}).decode("utf-8")},
                queue=True
            )
            if i == 10:
                first_command = cmd
                result = {
                    "CommandUUID": str(cmd.uuid),
                    "Status": "Acknowledged",
                    "UDID": device_udid
                }
                cmd.db_command.result = plistlib.dumps(result)
                cmd.db_command.save()
            elif i == 9:
                second_command = cmd
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, "CustomCommand (DeviceInformation)")
        self.assertEqual(response.context["commands_count"], 11)
        self.assertEqual(len(response.context["loaded_commands"]), 10)
        self.assertContains(response, "See all commands")
        self.assertContains(
            response,
            reverse("mdm:download_enrolled_device_command_result", args=(first_command.db_command.uuid,))
        )
        self.assertNotContains(
            response,
            reverse("mdm:download_enrolled_device_command_result", args=(second_command.db_command.uuid,))
        )

    def test_enrolled_device_apple_silicon_none(self):
        session, device_udid, serial_number = force_user_enrollment_session(self.mbu, completed=True)
        self.assertIsNone(session.enrolled_device.apple_silicon)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertNotContains(response, "Intel")
        self.assertNotContains(response, "Apple silicon")

    def test_enrolled_device_apple_silicon_true(self):
        session, device_udid, serial_number = force_user_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.apple_silicon = True
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertNotContains(response, "Intel")
        self.assertContains(response, "Apple silicon")

    def test_enrolled_device_apple_silicon_false(self):
        session, device_udid, serial_number = force_user_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.apple_silicon = False
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, "Intel")
        self.assertNotContains(response, "Apple silicon")

    # test enrolled device target artifacts

    def test_enrolled_device_target_artifact_installed(self):
        session, _, _ = force_user_enrollment_session(self.mbu, completed=True)
        artifact, (profile_av,) = force_artifact()
        da = DeviceArtifact.objects.create(
            enrolled_device=session.enrolled_device,
            artifact_version=profile_av,
            status=TargetArtifact.Status.INSTALLED,
            extra_info={"valid": "valid", "active": True}
        )
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, artifact.name)
        self.assertNotContains(response, f"mi-{da.pk}")

    def test_enrolled_device_target_artifact_failed(self):
        session, _, _ = force_user_enrollment_session(self.mbu, completed=True)
        artifact, (profile_av,) = force_artifact()
        error = get_random_string(12)
        da = DeviceArtifact.objects.create(
            enrolled_device=session.enrolled_device,
            artifact_version=profile_av,
            status=TargetArtifact.Status.FAILED,
            extra_info={"valid": "invalid", "active": True,
                        "reasons": [{"details": {"Error": error},
                                     "description": "Configuration cannot be applied",
                                     "code": "Error.ConfigurationCannotBeApplied"}]}
        )
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, artifact.name)
        self.assertContains(response, f"mi-{da.pk}")
        self.assertContains(response, error)
        self.assertContains(response, "Configuration cannot be applied")
        self.assertContains(response, "Error.ConfigurationCannotBeApplied")

    # test enrolled device commands

    def test_enrolled_device_commands_redirect(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login_redirect(reverse("mdm:enrolled_device_commands", args=(session.enrolled_device.pk,)))

    def test_enrolled_device_commands_permission_denied(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login()
        response = self.client.get(reverse("mdm:enrolled_device_commands", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.mdm.views.management.EnrolledDeviceCommandsView.get_paginate_by")
    def test_enrolled_device_commands(self, get_paginate_by):
        get_paginate_by.return_value = 2
        session, device_udid, serial_number = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        first_command = second_command = None
        for i in range(5):
            cmd = CustomCommand.create_for_device(
                session.enrolled_device,
                kwargs={"command": plistlib.dumps({"RequestType": "DeviceInformation"}).decode("utf-8")},
                queue=True
            )
            if i == 2:
                first_command = cmd
                result = {
                    "CommandUUID": str(cmd.uuid),
                    "Status": "Acknowledged",
                    "UDID": device_udid
                }
                cmd.db_command.result = plistlib.dumps(result)
                cmd.db_command.save()
            elif i == 1:
                second_command = cmd
        response = self.client.get(
            reverse("mdm:enrolled_device_commands", args=(session.enrolled_device.pk,)),
            {"page": 2}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/devicecommand_list.html")
        self.assertContains(response, "CustomCommand (DeviceInformation)")
        self.assertContains(response, "page 2 of 3")
        self.assertContains(
            response,
            reverse("mdm:download_enrolled_device_command_result", args=(first_command.db_command.uuid,))
        )
        self.assertNotContains(
            response,
            reverse("mdm:download_enrolled_device_command_result", args=(second_command.db_command.uuid,))
        )

    # create custom command

    def test_enrolled_device_no_custom_command_link(self):
        session, _, _ = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertNotContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "CustomCommand"))
        )

    def test_enrolled_device_custom_command_link(self):
        session, _, _ = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "CustomCommand"))
        )

    def test_create_enrolled_device_custom_command_redirect(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login_redirect(reverse("mdm:create_enrolled_device_command",
                                     args=(session.enrolled_device.pk, "CustomCommand")))

    def test_create_enrolled_device_custom_command_permission_denied(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "CustomCommand"))
        )
        self.assertEqual(response.status_code, 403)

    def test_create_enrolled_device_custom_command_get(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.add_devicecommand")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "CustomCommand"))
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")

    def test_create_enrolled_device_unknown_command_get_error(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.add_devicecommand")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "UnknownCommand"))
        )
        self.assertEqual(response.status_code, 400)

    def test_create_enrolled_device_custom_command_invalid_property_list(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "CustomCommand")),
            {"command": "YOLO"}
        )
        self.assertFormError(response.context["form"], "command", "Invalid property list")

    def test_create_enrolled_device_custom_command_not_a_dictionary(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "CustomCommand")),
            {"command": '<plist version="1.0"><array></array></plist>'}
        )
        self.assertFormError(response.context["form"], "command", "Not a dictionary")

    def test_create_enrolled_device_custom_command_missing_or_empty_request_type(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "CustomCommand")),
            {"command": "<dict></dict>"}
        )
        self.assertFormError(response.context["form"], "command", "Missing or empty RequestType")

    def test_create_enrolled_device_custom_command_ok(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "CustomCommand")),
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

    # create device information command

    def test_enrolled_device_no_device_information_command_link(self):
        session, _, _ = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertNotContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "DeviceInformation"))
        )

    def test_enrolled_device_device_information_command_link(self):
        session, _, _ = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "DeviceInformation"))
        )

    def test_create_enrolled_device_device_information_command_redirect(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login_redirect(reverse("mdm:create_enrolled_device_command",
                                     args=(session.enrolled_device.pk, "DeviceInformation")))

    def test_create_enrolled_device_device_information_command_permission_denied(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "DeviceInformation"))
        )
        self.assertEqual(response.status_code, 403)

    def test_create_enrolled_device_device_information_command_get(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.add_devicecommand")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "DeviceInformation"))
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")

    def test_create_enrolled_device_device_information_command_ok(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "DeviceInformation")),
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, "Device information command successfully created")
        command = session.enrolled_device.commands.first()
        self.assertEqual(command.name, "DeviceInformation")

    # create device lock command

    def test_enrolled_device_no_device_lock_command_link(self):
        session, _, _ = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertNotContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "DeviceLock"))
        )

    def test_enrolled_device_device_lock_command_link(self):
        session, _, _ = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "DeviceLock"))
        )

    def test_create_enrolled_device_device_lock_command_redirect(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login_redirect(reverse("mdm:create_enrolled_device_command",
                                     args=(session.enrolled_device.pk, "DeviceLock")))

    def test_create_enrolled_device_device_lock_command_permission_denied(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "DeviceLock"))
        )
        self.assertEqual(response.status_code, 403)

    def test_create_enrolled_device_device_lock_command_get(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.add_devicecommand")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "DeviceLock"))
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")
        self.assertContains(response, 'id="id_message"')
        self.assertContains(response, 'id="id_phone_number"')
        self.assertContains(response, 'id="id_pin"')

    def test_create_enrolled_device_device_lock_command_ios_get(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.platform = Platform.IOS
        session.enrolled_device.save()
        self._login("mdm.add_devicecommand")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "DeviceLock"))
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")
        self.assertContains(response, 'id="id_message"')
        self.assertContains(response, 'id="id_phone_number"')
        self.assertNotContains(response, 'id="id_pin"')

    def test_create_enrolled_device_device_lock_command_ok(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "DeviceLock")),
            {"message": "Yolo Fomo",
             "phone_number": "+123456789",
             "pin": "123456"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, "Device lock command successfully created")
        db_cmd = session.enrolled_device.commands.first()
        self.assertEqual(db_cmd.name, "DeviceLock")
        cmd = load_command(db_cmd)
        self.assertEqual(
            cmd.build_command(),
            {"Message": "Yolo Fomo",
             "PhoneNumber": "+123456789",
             "PIN": "123456"}
        )

    def test_create_enrolled_device_device_lock_command_ios_ok(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.platform = Platform.IOS
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "DeviceLock")),
            {"message": "Yolo Fomo",
             "phone_number": "+123456789"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, "Device lock command successfully created")
        db_cmd = session.enrolled_device.commands.first()
        self.assertEqual(db_cmd.name, "DeviceLock")
        cmd = load_command(db_cmd)
        self.assertEqual(
            cmd.build_command(),
            {"Message": "Yolo Fomo",
             "PhoneNumber": "+123456789"},
        )

    # create restart device command

    def test_enrolled_device_no_restart_device_command_link(self):
        session, _, _ = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertNotContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "RestartDevice"))
        )

    def test_enrolled_device_restart_device_command_link(self):
        session, _, _ = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "RestartDevice"))
        )

    def test_create_enrolled_device_restart_device_command_redirect(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login_redirect(reverse("mdm:create_enrolled_device_command",
                                     args=(session.enrolled_device.pk, "RestartDevice")))

    def test_create_enrolled_device_restart_device_command_permission_denied(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "RestartDevice"))
        )
        self.assertEqual(response.status_code, 403)

    def test_create_enrolled_device_restart_device_command_get(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.os_version = "11.3"
        session.enrolled_device.save()
        self._login("mdm.add_devicecommand")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "RestartDevice"))
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")
        self.assertContains(response, 'id="id_notify_user"')

    def test_create_enrolled_device_restart_device_command_older_os_get(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.os_version = "11.2"
        session.enrolled_device.save()
        self._login("mdm.add_devicecommand")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "RestartDevice"))
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")
        self.assertNotContains(response, 'id="id_notify_user"')

    def test_create_enrolled_device_restart_device_command_ios_get(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.supervised = True
        session.enrolled_device.platform = Platform.IOS
        session.enrolled_device.save()
        self._login("mdm.add_devicecommand")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "RestartDevice"))
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")
        self.assertNotContains(response, 'id="id_notify_user"')

    def test_create_enrolled_device_restart_device_command_ok(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.os_version = "11.3"
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "RestartDevice")),
            {"notify_user": "on"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, "Restart device command successfully created")
        db_cmd = session.enrolled_device.commands.first()
        self.assertEqual(db_cmd.name, "RestartDevice")
        cmd = load_command(db_cmd)
        self.assertEqual(
            cmd.build_command(),
            {"NotifyUser": True},
        )

    def test_create_enrolled_device_restart_device_command_unsupervised_ios_not_ok(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.platform = Platform.IOS
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "RestartDevice")),
            follow=True
        )
        self.assertEqual(response.status_code, 400)

    def test_create_enrolled_device_restart_device_command_ios_ok(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.supervised = True
        session.enrolled_device.platform = Platform.IOS
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "RestartDevice")),
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, "Restart device command successfully created")
        db_cmd = session.enrolled_device.commands.first()
        self.assertEqual(db_cmd.name, "RestartDevice")
        cmd = load_command(db_cmd)
        self.assertEqual(
            cmd.build_command(),
            {},
        )

    # create security info command

    def test_enrolled_device_no_security_info_command_link(self):
        session, _, _ = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertNotContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "SecurityInfo"))
        )

    def test_enrolled_device_security_info_command_link(self):
        session, _, _ = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "SecurityInfo"))
        )

    def test_create_enrolled_device_security_info_command_redirect(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login_redirect(reverse("mdm:create_enrolled_device_command",
                                     args=(session.enrolled_device.pk, "SecurityInfo")))

    def test_create_enrolled_device_security_info_command_permission_denied(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SecurityInfo"))
        )
        self.assertEqual(response.status_code, 403)

    def test_create_enrolled_device_security_info_command_get(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.add_devicecommand")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SecurityInfo"))
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")

    def test_create_enrolled_device_security_info_command_ok(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SecurityInfo")),
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, "Security info command successfully created")
        command = session.enrolled_device.commands.first()
        self.assertEqual(command.name, "SecurityInfo")

    # create set recovery lock command

    def test_enrolled_device_no_perms_no_set_recovery_lock_command_link(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.apple_silicon = True
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertNotContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "SetRecoveryLock"))
        )

    def test_enrolled_device_not_apple_silicon_no_set_recovery_lock_command_link(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self.assertFalse(session.enrolled_device.apple_silicon)
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertNotContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "SetRecoveryLock"))
        )

    def test_enrolled_device_set_recovery_lock_command_link(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.apple_silicon = True
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "SetRecoveryLock"))
        )

    def test_create_enrolled_device_set_recovery_lock_command_redirect(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.apple_silicon = True
        session.enrolled_device.save()
        self._login_redirect(reverse("mdm:create_enrolled_device_command",
                                     args=(session.enrolled_device.pk, "SetRecoveryLock")))

    def test_create_enrolled_device_set_recovery_lock_command_permission_denied(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.apple_silicon = True
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetRecoveryLock"))
        )
        self.assertEqual(response.status_code, 403)

    def test_create_enrolled_device_set_recovery_lock_command_get(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.apple_silicon = True
        session.enrolled_device.save()
        self._login("mdm.add_devicecommand")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetRecoveryLock"))
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")

    def test_create_enrolled_device_set_recovery_lock_command_pwd_too_short(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.apple_silicon = True
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetRecoveryLock")),
            {"new_password": "1234567"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")
        self.assertFormError(
            response.context["form"],
            "new_password",
            "The password must be at least 8 characters long."
        )

    def test_create_enrolled_device_set_recovery_lock_command_pwd_too_long(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.apple_silicon = True
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetRecoveryLock")),
            {"new_password": 33 * "1"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")
        self.assertFormError(
            response.context["form"],
            "new_password",
            "The password must be at most 32 characters long."
        )

    def test_create_enrolled_device_set_recovery_lock_command_pwd_non_ascii(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.apple_silicon = True
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetRecoveryLock")),
            {"new_password": 8 * "é"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")
        self.assertFormError(
            response.context["form"],
            "new_password",
            "The characters in this value must consist of low-ASCII, printable characters (0x20 through 0x7E) "
            "to ensure that all characters are enterable on the EFI login screen."
        )

    def test_create_enrolled_device_set_recovery_lock_command_pwd_clear_non_existing(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.apple_silicon = True
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetRecoveryLock")),
            {"new_password": ""},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")
        self.assertFormError(
            response.context["form"],
            "new_password",
            "No current recovery lock set: this field is required."
        )

    def test_create_enrolled_device_set_recovery_lock_command_ok(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.set_recovery_password("87654321")
        session.enrolled_device.apple_silicon = True
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetRecoveryLock")),
            {"new_password": "12345678"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, "Set recovery lock command successfully created")
        db_cmd = session.enrolled_device.commands.first()
        self.assertEqual(db_cmd.name, "SetRecoveryLock")
        cmd = load_command(db_cmd)
        self.assertEqual(
            cmd.build_command(),
            {"CurrentPassword": "87654321",
             "NewPassword": "12345678"},
        )

    def test_create_enrolled_device_set_recovery_lock_command_clear_ok(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.set_recovery_password("87654321")
        session.enrolled_device.apple_silicon = True
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetRecoveryLock")),
            {"new_password": ""},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, "Set recovery lock command successfully created")
        db_cmd = session.enrolled_device.commands.first()
        self.assertEqual(db_cmd.name, "SetRecoveryLock")
        cmd = load_command(db_cmd)
        self.assertEqual(
            cmd.build_command(),
            {"CurrentPassword": "87654321",
             "NewPassword": ""},
        )

    # create set firmware password command

    def test_enrolled_device_no_perms_no_set_firmware_password_command_link(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self.assertFalse(session.enrolled_device.apple_silicon)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertNotContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "SetFirmwarePassword"))
        )

    def test_enrolled_device_apple_silicon_no_set_firmware_password_command_link(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.apple_silicon = True
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertNotContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "SetFirmwarePassword"))
        )

    def test_enrolled_device_set_firmware_password_command_link(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "SetFirmwarePassword"))
        )

    def test_create_enrolled_device_set_firmware_password_command_redirect(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login_redirect(reverse("mdm:create_enrolled_device_command",
                                     args=(session.enrolled_device.pk, "SetFirmwarePassword")))

    def test_create_enrolled_device_set_firmware_password_command_permission_denied(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetFirmwarePassword"))
        )
        self.assertEqual(response.status_code, 403)

    def test_create_enrolled_device_set_firmware_password_command_get(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.add_devicecommand")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetFirmwarePassword"))
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")

    def test_create_enrolled_device_set_firmware_password_command_pwd_too_short(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetFirmwarePassword")),
            {"new_password": "1234567"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")
        self.assertFormError(
            response.context["form"],
            "new_password",
            "The password must be at least 8 characters long."
        )

    def test_create_enrolled_device_set_firmware_password_command_pwd_too_long(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetFirmwarePassword")),
            {"new_password": 33 * "1"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")
        self.assertFormError(
            response.context["form"],
            "new_password",
            "The password must be at most 32 characters long."
        )

    def test_create_enrolled_device_set_firmware_password_command_pwd_non_ascii(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetFirmwarePassword")),
            {"new_password": 8 * "é"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")
        self.assertFormError(
            response.context["form"],
            "new_password",
            "The characters in this value must consist of low-ASCII, printable characters (0x20 through 0x7E) "
            "to ensure that all characters are enterable on the EFI login screen."
        )

    def test_create_enrolled_device_set_firmware_password_command_pwd_clear_non_existing(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetFirmwarePassword")),
            {"new_password": ""},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")
        self.assertFormError(
            response.context["form"],
            "new_password",
            "No current firmware password set: this field is required."
        )

    def test_create_enrolled_device_set_firmware_password_command_ok(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.set_recovery_password("87654321")
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetFirmwarePassword")),
            {"new_password": "12345678"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, "Set firmware password command successfully created")
        db_cmd = session.enrolled_device.commands.first()
        self.assertEqual(db_cmd.name, "SetFirmwarePassword")
        cmd = load_command(db_cmd)
        self.assertEqual(
            cmd.build_command(),
            {"CurrentPassword": "87654321",
             "NewPassword": "12345678"},
        )

    def test_create_enrolled_device_set_firmware_password_command_clear_ok(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.set_recovery_password("87654321")
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetFirmwarePassword")),
            {"new_password": ""},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, "Set firmware password command successfully created")
        db_cmd = session.enrolled_device.commands.first()
        self.assertEqual(db_cmd.name, "SetFirmwarePassword")
        cmd = load_command(db_cmd)
        self.assertEqual(
            cmd.build_command(),
            {"CurrentPassword": "87654321",
             "NewPassword": ""},
        )

    # create set auto admin password command

    def test_enrolled_device_no_perms_no_set_auto_admin_password_command_link(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.device_information = {
            "AutoSetupAdminAccounts": [
                {"GUID": "yolo", "shortName": "fomo"}
            ]
        }
        session.enrolled_device.save()
        self.assertEqual(session.enrolled_device.admin_guid, "yolo")
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertNotContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "SetAutoAdminPassword"))
        )

    def test_enrolled_device_no_guid_no_set_auto_admin_password_command_link(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self.assertIsNone(session.enrolled_device.admin_guid)
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertNotContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "SetAutoAdminPassword"))
        )

    def test_enrolled_device_set_auto_admin_password_command_link(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.device_information = {
            "AutoSetupAdminAccounts": [
                {"GUID": "yolo", "shortName": "fomo"}
            ]
        }
        session.enrolled_device.save()
        self.assertEqual(session.enrolled_device.admin_guid, "yolo")
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "SetAutoAdminPassword"))
        )

    def test_create_enrolled_device_set_auto_admin_password_command_redirect(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.device_information = {
            "AutoSetupAdminAccounts": [
                {"GUID": "yolo", "shortName": "fomo"}
            ]
        }
        session.enrolled_device.save()
        self._login_redirect(reverse("mdm:create_enrolled_device_command",
                                     args=(session.enrolled_device.pk, "SetAutoAdminPassword")))

    def test_create_enrolled_device_set_auto_admin_password_command_permission_denied(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.device_information = {
            "AutoSetupAdminAccounts": [
                {"GUID": "yolo", "shortName": "fomo"}
            ]
        }
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetAutoAdminPassword"))
        )
        self.assertEqual(response.status_code, 403)

    def test_create_enrolled_device_set_auto_admin_password_command_get(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.device_information = {
            "AutoSetupAdminAccounts": [
                {"GUID": "yolo", "shortName": "fomo"}
            ]
        }
        session.enrolled_device.save()
        self._login("mdm.add_devicecommand")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetAutoAdminPassword"))
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")

    def test_create_enrolled_device_set_auto_admin_password_command_ok(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.device_information = {
            "AutoSetupAdminAccounts": [
                {"GUID": "yolo", "shortName": "fomo"}
            ]
        }
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetAutoAdminPassword")),
            {"new_password": "12345678"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, "Set auto admin password command successfully created")
        db_cmd = session.enrolled_device.commands.first()
        self.assertEqual(db_cmd.name, "SetAutoAdminPassword")
        cmd = load_command(db_cmd)
        payload = cmd.build_command()
        self.assertEqual(set(payload.keys()), {"GUID", "passwordHash"})
        self.assertEqual(payload["GUID"], "yolo")
        ph = plistlib.loads(payload["passwordHash"])
        self.assertEqual(list(ph.keys()), ["SALTED-SHA512-PBKDF2"])

    def test_create_enrolled_device_set_auto_admin_password_command_default_ok(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.device_information = {
            "AutoSetupAdminAccounts": [
                {"GUID": "yolo", "shortName": "fomo"}
            ]
        }
        session.enrolled_device.save()
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "SetAutoAdminPassword")),
            {},  # no password
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, "Set auto admin password command successfully created")
        db_cmd = session.enrolled_device.commands.first()
        self.assertEqual(db_cmd.name, "SetAutoAdminPassword")
        cmd = load_command(db_cmd)
        payload = cmd.build_command()
        self.assertEqual(set(payload.keys()), {"GUID", "passwordHash"})
        self.assertEqual(payload["GUID"], "yolo")
        ph = plistlib.loads(payload["passwordHash"])
        self.assertEqual(list(ph.keys()), ["SALTED-SHA512-PBKDF2"])

    # create rotate filevault key command

    def test_enrolled_device_no_rotate_filevault_key_command_link(self):
        session, _, _ = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertNotContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "RotateFileVaultKey"))
        )

    def test_enrolled_device_no_prk_no_rotate_filevault_key_command_link(self):
        session, _, _ = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertNotContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "RotateFileVaultKey"))
        )

    def test_enrolled_device_rotate_filevault_key_command_link(self):
        session, _, _ = force_user_enrollment_session(self.mbu, completed=True)
        enrolled_device = session.enrolled_device
        enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        enrolled_device.save()
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(
            response,
            reverse("mdm:create_enrolled_device_command", args=(session.enrolled_device.pk, "RotateFileVaultKey"))
        )

    def test_create_enrolled_device_rotate_filevault_key_command_redirect(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        enrolled_device = session.enrolled_device
        enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        enrolled_device.save()
        self._login_redirect(reverse("mdm:create_enrolled_device_command",
                                     args=(session.enrolled_device.pk, "RotateFileVaultKey")))

    def test_create_enrolled_device_rotate_filevault_key_command_permission_denied(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        enrolled_device = session.enrolled_device
        enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        enrolled_device.save()
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "RotateFileVaultKey"))
        )
        self.assertEqual(response.status_code, 403)

    def test_create_enrolled_device_rotate_filevault_key_command_get(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        enrolled_device = session.enrolled_device
        enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        enrolled_device.save()
        self._login("mdm.add_devicecommand")
        response = self.client.get(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "RotateFileVaultKey"))
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_create_command.html")

    def test_create_enrolled_device_rotate_filevault_key_command_ok(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        enrolled_device = session.enrolled_device
        enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        enrolled_device.save()
        self._login("mdm.view_enrolleddevice", "mdm.add_devicecommand")
        response = self.client.post(
            reverse("mdm:create_enrolled_device_command",
                    args=(session.enrolled_device.pk, "RotateFileVaultKey")),
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, "Rotate FileVault key command successfully created")
        command = session.enrolled_device.commands.first()
        self.assertEqual(command.name, "RotateFileVaultKey")

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

    # change blueprint

    def test_change_enrolled_device_blueprint_redirect(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login_redirect(reverse("mdm:change_enrolled_device_blueprint", args=(session.enrolled_device.pk,)))

    def test_change_enrolled_device_blueprint_permission_denied(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login()
        response = self.client.get(reverse("mdm:change_enrolled_device_blueprint", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_change_enrolled_device_blueprint_get(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.change_enrolleddevice")
        response = self.client.get(reverse("mdm:change_enrolled_device_blueprint", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_form.html")
        self.assertContains(response, "Change blueprint")

    @patch("zentral.contrib.mdm.views.management.send_enrolled_device_notification")
    def test_change_enrolled_device_blueprint_post(self, send_enrolled_device_notification):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self.assertIsNone(session.enrolled_device.blueprint)
        self._login("mdm.change_enrolleddevice", "mdm.view_enrolleddevice")
        blueprint = Blueprint.objects.create(name=get_random_string(12))
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("mdm:change_enrolled_device_blueprint", args=(session.enrolled_device.pk,)),
                {"blueprint": blueprint.pk},
                follow=True
            )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertEqual(len(callbacks), 1)
        send_enrolled_device_notification.assert_called_once_with(session.enrolled_device)
        session.enrolled_device.refresh_from_db()
        self.assertEqual(session.enrolled_device.blueprint, blueprint)
        self.assertContains(response, blueprint.name)

    # block

    def test_block_enrolled_device_redirect(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login_redirect(reverse("mdm:block_enrolled_device", args=(session.enrolled_device.pk,)))

    def test_block_enrolled_device_permission_denied(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login()
        response = self.client.get(reverse("mdm:block_enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_block_enrolled_device_get(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.change_enrolleddevice")
        response = self.client.get(reverse("mdm:block_enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_confirm_block.html")
        self.assertContains(response, f"Block device {session.enrolled_device.udid}")

    def test_block_blocked_enrolled_device_404(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.block()
        self._login("mdm.change_enrolleddevice")
        response = self.client.get(reverse("mdm:block_enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 404)

    @patch("zentral.contrib.mdm.views.management.send_enrolled_device_notification")
    def test_block_enrolled_device_post(self, send_enrolled_device_notification):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self.assertIsNone(session.enrolled_device.blocked_at)
        self._login("mdm.change_enrolleddevice", "mdm.view_enrolleddevice")

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("mdm:block_enrolled_device", args=(session.enrolled_device.pk,)),
                follow=True
            )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertEqual(len(callbacks), 1)
        send_enrolled_device_notification.assert_called_once_with(session.enrolled_device)
        session.enrolled_device.refresh_from_db()
        self.assertIsNotNone(session.enrolled_device.blocked_at)

    # ununblock

    def test_unblock_enrolled_device_redirect(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login_redirect(reverse("mdm:unblock_enrolled_device", args=(session.enrolled_device.pk,)))

    def test_unblock_enrolled_device_permission_denied(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login()
        response = self.client.get(reverse("mdm:unblock_enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_unblock_enrolled_device_get(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.block()
        self._login("mdm.change_enrolleddevice")
        response = self.client.get(reverse("mdm:unblock_enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_confirm_unblock.html")
        self.assertContains(response, f"Unblock device {session.enrolled_device.udid}")

    def test_unblock_unblocked_enrolled_device_404(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.change_enrolleddevice")
        response = self.client.get(reverse("mdm:unblock_enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_unblock_enrolled_device_post(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.block()
        self._login("mdm.change_enrolleddevice", "mdm.view_enrolleddevice")
        response = self.client.post(
            reverse("mdm:unblock_enrolled_device", args=(session.enrolled_device.pk,)),
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        session.enrolled_device.refresh_from_db()
        self.assertIsNone(session.enrolled_device.blocked_at)
