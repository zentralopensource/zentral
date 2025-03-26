from functools import reduce
import operator
from urllib.parse import urlencode
import uuid
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import APIToken, User
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import DeviceInformation, DeviceLock, InstallProfile
from zentral.contrib.mdm.models import Channel
from .utils import force_artifact, force_dep_enrollment_session, force_enrolled_user


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class APIViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.user.groups.set([cls.group])
        cls.api_key = APIToken.objects.update_or_create_for_user(cls.service_account)
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.dep_enrollment_session, _, _ = force_dep_enrollment_session(
            cls.mbu, authenticated=True, completed=True
        )
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device
        cls.enrolled_user = force_enrolled_user(cls.enrolled_device)

    # utility methods

    def set_permissions(self, *permissions):
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

    def login(self, *permissions):
        self.set_permissions(*permissions)
        self.client.force_login(self.user)

    def login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def get(self, url, include_token=True):
        kwargs = {}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.get(url, **kwargs)

    def post(self, url, data, include_token=True):
        kwargs = {"content_type": "application/json"}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.post(url, data, **kwargs)

    # device commands

    def test_enrolled_device_commands_unauthorized(self):
        response = self.get(reverse("mdm_api:enrolled_device_commands"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_enrolled_device_commands_permission_denied(self):
        response = self.get(reverse("mdm_api:enrolled_device_commands"))
        self.assertEqual(response.status_code, 403)

    def test_enrolled_devices_method_not_allowed(self):
        self.set_permissions("mdm.add_devicecommand")
        response = self.post(reverse("mdm_api:enrolled_device_commands"), {})
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.json(), {'detail': 'Method "POST" not allowed.'})

    def test_enrolled_devices_commands(self):
        self.set_permissions("mdm.view_devicecommand")
        message = get_random_string(12)
        phone_number = get_random_string(12)
        cmd_uuid = uuid.uuid4()
        cmd = DeviceLock.create_for_device(
            self.enrolled_device,
            kwargs={"Message": message,
                    "PhoneNumber": phone_number},
            queue=True,
            uuid=cmd_uuid,
        )
        db_cmd = cmd.db_command
        response = self.get(reverse("mdm_api:enrolled_device_commands"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'count': 1,
             'next': None,
             'previous': None,
             'results': [
                 {'artifact_operation': None,
                  'artifact_version': None,
                  'created_at': db_cmd.created_at.isoformat(),
                  'enrolled_device': self.enrolled_device.pk,
                  'error_chain': None,
                  'name': 'DeviceLock',
                  'not_before': None,
                  'result': None,
                  'result_time': None,
                  'status': None,
                  'time': None,
                  'updated_at': db_cmd.updated_at.isoformat(),
                  'uuid': str(cmd.uuid)}
             ]}
        )

    def test_enrolled_devices_commands_filter_by_name(self):
        self.set_permissions("mdm.view_devicecommand")
        message = get_random_string(12)
        phone_number = get_random_string(12)
        cmd_uuid = uuid.uuid4()
        cmd = DeviceLock.create_for_device(
            self.enrolled_device,
            kwargs={"Message": message,
                    "PhoneNumber": phone_number},
            queue=True,
            uuid=cmd_uuid,
        )
        db_cmd = cmd.db_command
        DeviceInformation.create_for_device(self.enrolled_device)
        response = self.get(reverse("mdm_api:enrolled_device_commands")
                            + "?" + urlencode({"name": "DeviceLock"}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'count': 1,
             'next': None,
             'previous': None,
             'results': [
                 {'artifact_operation': None,
                  'artifact_version': None,
                  'created_at': db_cmd.created_at.isoformat(),
                  'enrolled_device': self.enrolled_device.pk,
                  'error_chain': None,
                  'name': 'DeviceLock',
                  'not_before': None,
                  'result': None,
                  'result_time': None,
                  'status': None,
                  'time': None,
                  'updated_at': db_cmd.updated_at.isoformat(),
                  'uuid': str(cmd.uuid)}
             ]}
        )

    def test_enrolled_devices_commands_filter_by_enrolled_device(self):
        cmd = DeviceInformation.create_for_device(self.enrolled_device)
        db_cmd = cmd.db_command
        dep_enrollment_session2, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        DeviceInformation.create_for_device(dep_enrollment_session2.enrolled_device)
        self.set_permissions("mdm.view_devicecommand")
        response = self.get(reverse("mdm_api:enrolled_device_commands")
                            + "?" + urlencode({"enrolled_device": self.enrolled_device.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'count': 1,
             'next': None,
             'previous': None,
             'results': [
                 {'artifact_operation': None,
                  'artifact_version': None,
                  'created_at': db_cmd.created_at.isoformat(),
                  'enrolled_device': self.enrolled_device.pk,
                  'error_chain': None,
                  'name': 'DeviceInformation',
                  'not_before': None,
                  'result': None,
                  'result_time': None,
                  'status': None,
                  'time': db_cmd.time.isoformat(),
                  'updated_at': db_cmd.updated_at.isoformat(),
                  'uuid': str(cmd.uuid)}
             ]}
        )

    # device command

    def test_enrolled_device_command_unauthorized(self):
        cmd = DeviceInformation.create_for_device(self.enrolled_device)
        response = self.get(reverse("mdm_api:enrolled_device_command", args=(cmd.uuid,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_enrolled_device_command_permission_denied(self):
        cmd = DeviceInformation.create_for_device(self.enrolled_device)
        response = self.get(reverse("mdm_api:enrolled_device_command", args=(cmd.uuid,)))
        self.assertEqual(response.status_code, 403)

    def test_enrolled_device_command(self):
        message = get_random_string(12)
        phone_number = get_random_string(12)
        cmd_uuid = uuid.uuid4()
        cmd = DeviceLock.create_for_device(
            self.enrolled_device,
            kwargs={"Message": message,
                    "PhoneNumber": phone_number},
            uuid=cmd_uuid,
        )
        db_cmd = cmd.db_command
        self.set_permissions("mdm.view_devicecommand")
        response = self.get(reverse("mdm_api:enrolled_device_command", args=(cmd.uuid,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'artifact_operation': None,
             'artifact_version': None,
             'created_at': db_cmd.created_at.isoformat(),
             'enrolled_device': self.enrolled_device.pk,
             'error_chain': None,
             'name': 'DeviceLock',
             'not_before': None,
             'result': None,
             'result_time': None,
             'status': None,
             'time': db_cmd.time.isoformat(),
             'updated_at': db_cmd.updated_at.isoformat(),
             'uuid': str(cmd.uuid)}
        )

    # user commands

    def test_enrolled_user_commands_unauthorized(self):
        response = self.get(reverse("mdm_api:enrolled_user_commands"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_enrolled_user_commands_permission_denied(self):
        response = self.get(reverse("mdm_api:enrolled_user_commands"))
        self.assertEqual(response.status_code, 403)

    def test_enrolled_user_commands_method_not_allowed(self):
        self.set_permissions("mdm.add_usercommand")
        response = self.post(reverse("mdm_api:enrolled_user_commands"), {})
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.json(), {'detail': 'Method "POST" not allowed.'})

    def test_enrolled_user_commands(self):
        self.set_permissions("mdm.view_usercommand")
        a, (av,) = force_artifact(channel=Channel.USER, version_count=1)
        cmd = InstallProfile.create_for_target(Target(self.enrolled_device, self.enrolled_user), artifact_version=av)
        db_cmd = cmd.db_command
        response = self.get(reverse("mdm_api:enrolled_user_commands"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'count': 1,
             'next': None,
             'previous': None,
             'results': [{'artifact_operation': 'INSTALLATION',
                          'artifact_version': str(av.pk),
                          'created_at': db_cmd.created_at.isoformat(),
                          'enrolled_user': self.enrolled_user.pk,
                          'error_chain': None,
                          'name': 'InstallProfile',
                          'not_before': None,
                          'result': None,
                          'result_time': None,
                          'status': None,
                          'time': db_cmd.time.isoformat(),
                          'updated_at': db_cmd.updated_at.isoformat(),
                          'uuid': str(cmd.uuid)}]}
        )

    def test_enrolled_user_commands_filter_by_name(self):
        self.set_permissions("mdm.view_usercommand")
        target = Target(self.enrolled_device, self.enrolled_user)
        DeviceInformation.create_for_target(target)
        a, (av,) = force_artifact(channel=Channel.USER, version_count=1)
        cmd = InstallProfile.create_for_target(target, artifact_version=av)
        db_cmd = cmd.db_command
        response = self.get(reverse("mdm_api:enrolled_user_commands")
                            + "?" + urlencode({"name": "InstallProfile"}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'count': 1,
             'next': None,
             'previous': None,
             'results': [{'artifact_operation': 'INSTALLATION',
                          'artifact_version': str(av.pk),
                          'created_at': db_cmd.created_at.isoformat(),
                          'enrolled_user': self.enrolled_user.pk,
                          'error_chain': None,
                          'name': 'InstallProfile',
                          'not_before': None,
                          'result': None,
                          'result_time': None,
                          'status': None,
                          'time': db_cmd.time.isoformat(),
                          'updated_at': db_cmd.updated_at.isoformat(),
                          'uuid': str(cmd.uuid)}]}
        )

    def test_enrolled_user_commands_filter_by_enrolled_user(self):
        self.set_permissions("mdm.view_usercommand")
        DeviceInformation.create_for_target(Target(self.enrolled_device, force_enrolled_user(self.enrolled_device)))
        a, (av,) = force_artifact(channel=Channel.USER, version_count=1)
        cmd = InstallProfile.create_for_target(Target(self.enrolled_device, self.enrolled_user), artifact_version=av)
        db_cmd = cmd.db_command
        response = self.get(reverse("mdm_api:enrolled_user_commands")
                            + "?" + urlencode({"name": "InstallProfile"}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'count': 1,
             'next': None,
             'previous': None,
             'results': [{'artifact_operation': 'INSTALLATION',
                          'artifact_version': str(av.pk),
                          'created_at': db_cmd.created_at.isoformat(),
                          'enrolled_user': self.enrolled_user.pk,
                          'error_chain': None,
                          'name': 'InstallProfile',
                          'not_before': None,
                          'result': None,
                          'result_time': None,
                          'status': None,
                          'time': db_cmd.time.isoformat(),
                          'updated_at': db_cmd.updated_at.isoformat(),
                          'uuid': str(cmd.uuid)}]}
        )

    # user command

    def test_enrolled_user_command_unauthorized(self):
        cmd = DeviceInformation.create_for_target(Target(self.enrolled_device, self.enrolled_user))
        response = self.get(reverse("mdm_api:enrolled_user_command", args=(cmd.uuid,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_enrolled_user_command_permission_denied(self):
        cmd = DeviceInformation.create_for_target(Target(self.enrolled_device, self.enrolled_user))
        response = self.get(reverse("mdm_api:enrolled_user_command", args=(cmd.uuid,)))
        self.assertEqual(response.status_code, 403)

    def test_enrolled_user_command_method_not_allowed(self):
        cmd = DeviceInformation.create_for_target(Target(self.enrolled_device, self.enrolled_user))
        self.set_permissions("mdm.add_usercommand")
        response = self.post(reverse("mdm_api:enrolled_user_command", args=(cmd.uuid,)), {})
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.json(), {'detail': 'Method "POST" not allowed.'})

    def test_enrolled_user_command(self):
        cmd = DeviceInformation.create_for_target(Target(self.enrolled_device, self.enrolled_user))
        db_cmd = cmd.db_command
        self.set_permissions("mdm.view_usercommand")
        response = self.get(reverse("mdm_api:enrolled_user_command", args=(cmd.uuid,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'artifact_operation': None,
             'artifact_version': None,
             'created_at': db_cmd.created_at.isoformat(),
             'enrolled_user': self.enrolled_user.pk,
             'error_chain': None,
             'name': 'DeviceInformation',
             'not_before': None,
             'result': None,
             'result_time': None,
             'status': None,
             'time': db_cmd.time.isoformat(),
             'updated_at': db_cmd.updated_at.isoformat(),
             'uuid': str(cmd.uuid)}
        )
