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
from .utils import force_dep_enrollment_session, force_enrolled_user


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class EnrolledUserManagementViewsTestCase(TestCase):
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

    def _force_enrolled_user(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        enrolled_user = force_enrolled_user(session.enrolled_device)
        return enrolled_user, session.enrolled_device

    # test enrolled user

    def test_enrolled_user_redirect(self):
        enrolled_user, enrolled_device = self._force_enrolled_user()
        self._login_redirect(reverse("mdm:enrolled_user", args=(enrolled_device.pk, enrolled_user.pk)))

    def test_enrolled_user_permission_denied(self):
        enrolled_user, enrolled_device = self._force_enrolled_user()
        self._login()
        response = self.client.get(reverse("mdm:enrolled_user", args=(enrolled_device.pk, enrolled_user.pk)))
        self.assertEqual(response.status_code, 403)

    def test_enrolled_user(self):
        enrolled_user, enrolled_device = self._force_enrolled_user()
        self._login("mdm.view_enrolleduser")
        response = self.client.get(reverse("mdm:enrolled_user", args=(enrolled_device.pk, enrolled_user.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleduser_detail.html")
        self.assertContains(response, enrolled_user.short_name)
        self.assertContains(response, enrolled_user.long_name)
        self.assertContains(response, enrolled_device.udid)
        self.assertContains(response, "0 Artifacts")
        self.assertContains(response, "Last commands")
        self.assertNotContains(response, "See all commands")

    def test_enrolled_user_one_command(self):
        enrolled_user, enrolled_device = self._force_enrolled_user()
        CustomCommand.create_for_user(
            enrolled_user,
            kwargs={"command": plistlib.dumps({"RequestType": "ProfileList"}).decode("utf-8")},
            queue=True
        )
        self._login("mdm.view_enrolleduser")
        response = self.client.get(reverse("mdm:enrolled_user", args=(enrolled_device.pk, enrolled_user.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleduser_detail.html")
        self.assertContains(response, "CustomCommand (ProfileList)")
        self.assertEqual(response.context["commands_count"], 1)
        self.assertEqual(len(response.context["loaded_commands"]), 1)
        self.assertNotContains(response, "See all commands")

    def test_enrolled_user_top_10_command(self):
        enrolled_user, enrolled_device = self._force_enrolled_user()
        first_command = second_command = None
        for i in range(11):
            cmd = CustomCommand.create_for_user(
                enrolled_user,
                kwargs={"command": plistlib.dumps({"RequestType": "ProfileList"}).decode("utf-8")},
                queue=True
            )
            if i == 10:
                first_command = cmd
                result = {
                    "CommandUUID": str(cmd.uuid),
                    "Status": "Acknowledged",
                    "UDID": enrolled_device.udid,
                    "UserID": enrolled_user.user_id,
                }
                cmd.db_command.result = plistlib.dumps(result)
                cmd.db_command.save()
            elif i == 9:
                second_command = cmd
        self._login("mdm.view_enrolleduser")
        response = self.client.get(reverse("mdm:enrolled_user", args=(enrolled_device.pk, enrolled_user.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleduser_detail.html")
        self.assertContains(response, "CustomCommand (ProfileList)")
        self.assertEqual(response.context["commands_count"], 11)
        self.assertEqual(len(response.context["loaded_commands"]), 10)
        self.assertContains(response, "See all commands")
        self.assertContains(
            response,
            reverse("mdm:download_enrolled_user_command_result", args=(first_command.db_command.uuid,))
        )
        self.assertNotContains(
            response,
            reverse("mdm:download_enrolled_user_command_result", args=(second_command.db_command.uuid,))
        )

    # test enrolled user commands

    def test_enrolled_user_commands_redirect(self):
        enrolled_user, enrolled_device = self._force_enrolled_user()
        self._login_redirect(reverse("mdm:enrolled_user_commands", args=(enrolled_device.pk, enrolled_user.pk)))

    def test_enrolled_user_commands_permission_denied(self):
        enrolled_user, enrolled_device = self._force_enrolled_user()
        self._login()
        response = self.client.get(reverse("mdm:enrolled_user_commands", args=(enrolled_device.pk, enrolled_user.pk)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.mdm.views.management.EnrolledUserCommandsView.get_paginate_by")
    def test_enrolled_user_commands(self, get_paginate_by):
        get_paginate_by.return_value = 2
        enrolled_user, enrolled_device = self._force_enrolled_user()
        first_command = second_command = None
        for i in range(5):
            cmd = CustomCommand.create_for_user(
                enrolled_user,
                kwargs={"command": plistlib.dumps({"RequestType": "ProfileList"}).decode("utf-8")},
                queue=True
            )
            if i == 2:
                first_command = cmd
                result = {
                    "CommandUUID": str(cmd.uuid),
                    "Status": "Acknowledged",
                    "UDID": enrolled_device.udid,
                    "UserID": enrolled_user.user_id,
                }
                cmd.db_command.result = plistlib.dumps(result)
                cmd.db_command.save()
            elif i == 1:
                second_command = cmd
        self._login("mdm.view_enrolleduser")
        response = self.client.get(
            reverse("mdm:enrolled_user_commands", args=(enrolled_device.pk, enrolled_user.pk)),
            {"page": 2}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/usercommand_list.html")
        self.assertContains(response, "CustomCommand (ProfileList)")
        self.assertContains(response, "page 2 of 3")
        self.assertContains(
            response,
            reverse("mdm:download_enrolled_user_command_result", args=(first_command.db_command.uuid,))
        )
        self.assertNotContains(
            response,
            reverse("mdm:download_enrolled_user_command_result", args=(second_command.db_command.uuid,))
        )

    # download custom command result

    def test_download_enrolled_user_command_result_redirect(self):
        enrolled_user, enrolled_device = self._force_enrolled_user()
        cmd = CustomCommand.create_for_user(
            enrolled_user,
            kwargs={"command": plistlib.dumps({"RequestType": "DeviceInformation"}).decode("utf-8")},
            queue=True
        )
        self._login_redirect(reverse("mdm:download_enrolled_user_command_result", args=(cmd.db_command.uuid,)))

    def test_download_enrolled_user_command_result_permission_denied(self):
        enrolled_user, enrolled_device = self._force_enrolled_user()
        cmd = CustomCommand.create_for_user(
            enrolled_user,
            kwargs={"command": plistlib.dumps({"RequestType": "DeviceInformation"}).decode("utf-8")},
            queue=True
        )
        self._login("mdm.view_enrolleduser")
        response = self.client.get(reverse("mdm:download_enrolled_user_command_result", args=(cmd.db_command.uuid,)))
        self.assertEqual(response.status_code, 403)

    def test_download_enrolled_user_command_result_no_result_404(self):
        enrolled_user, enrolled_device = self._force_enrolled_user()
        cmd = CustomCommand.create_for_user(
            enrolled_user,
            kwargs={"command": plistlib.dumps({"RequestType": "DeviceInformation"}).decode("utf-8")},
            queue=True
        )
        self._login("mdm.view_usercommand")
        response = self.client.get(reverse("mdm:download_enrolled_user_command_result", args=(cmd.db_command.uuid,)))
        self.assertEqual(response.status_code, 404)

    def test_download_enrolled_user_command_result(self):
        enrolled_user, enrolled_device = self._force_enrolled_user()
        cmd = CustomCommand.create_for_user(
            enrolled_user,
            kwargs={"command": plistlib.dumps({"RequestType": "DeviceInformation"}).decode("utf-8")},
            queue=True
        )
        # save result
        result = {
            "CommandUUID": "32771F87-6EE3-4347-B1D5-9F5AC5687711",
            "Status": "Acknowledged",
            "UDID": enrolled_device.udid,
            "UserID": enrolled_user.user_id,
        }
        cmd.db_command.result = plistlib.dumps(result)
        cmd.db_command.save()
        self._login("mdm.view_usercommand")
        response = self.client.get(reverse("mdm:download_enrolled_user_command_result", args=(cmd.db_command.uuid,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/x-plist")
        self.assertEqual(
            response["Content-Disposition"],
            f'attachment; filename="user_command_{cmd.db_command.uuid}-result.plist"'
        )
        self.assertEqual(plistlib.loads(b"".join(response.streaming_content)), result)
