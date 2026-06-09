from urllib.parse import urlencode
import uuid
from unittest.mock import patch
from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase

from accounts.models import APIToken, User
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import DeviceInformation, DeviceLock, InstallProfile
from zentral.contrib.mdm.models import Artifact, Channel, DeviceCommand
from zentral.core.events.base import AuditEvent
from .utils import force_artifact, force_dep_enrollment_session, force_enrolled_user


class APIViewsTestCase(TestCase, LoginCase, RequestCase):
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
        _, cls.api_key = APIToken.objects.create_for_user(cls.service_account)
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.dep_enrollment_session, _, _ = force_dep_enrollment_session(
            cls.mbu, authenticated=True, completed=True
        )
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device
        cls.enrolled_user = force_enrolled_user(cls.enrolled_device)

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "mdm_api"

    # RequestCase implementation

    def _get_api_key(self):
        return self.api_key

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

    def test_enrolled_device_command_delete_unauthorized(self):
        cmd = DeviceLock.create_for_device(self.enrolled_device, queue=True)
        response = self.delete(reverse("mdm_api:enrolled_device_command", args=(cmd.uuid,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_enrolled_device_command_delete_permission_denied(self):
        cmd = DeviceLock.create_for_device(self.enrolled_device, queue=True)
        self.set_permissions("mdm.view_devicecommand")
        response = self.delete(reverse("mdm_api:enrolled_device_command", args=(cmd.uuid,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enrolled_device_command_delete_queued(self, post_event):
        cmd = DeviceLock.create_for_device(self.enrolled_device, queue=True)
        prev_value = cmd.db_command.serialize_for_event()
        self.set_permissions("mdm.delete_devicecommand")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:enrolled_device_command", args=(cmd.uuid,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(DeviceCommand.objects.filter(uuid=cmd.uuid).count(), 0)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.devicecommand",
                 "pk": str(cmd.db_command.pk),
                 "prev_value": prev_value,
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_command": [str(cmd.uuid)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enrolled_device_command_delete_already_sent(self, post_event):
        cmd = DeviceInformation.create_for_device(self.enrolled_device)
        self.assertIsNotNone(cmd.db_command.time)
        self.set_permissions("mdm.delete_devicecommand")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:enrolled_device_command", args=(cmd.uuid,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            ["This command has already been sent to the device and cannot be deleted"]
        )
        self.assertEqual(DeviceCommand.objects.filter(uuid=cmd.uuid).count(), 1)
        self.assertEqual(len(callbacks), 0)
        post_event.assert_not_called()

    def test_device_command_serialize_for_event(self):
        a, (av,) = force_artifact(version_count=1)
        cmd = DeviceLock.create_for_device(self.enrolled_device, queue=True)
        db_command = cmd.db_command
        db_command.artifact_version = av
        db_command.artifact_operation = Artifact.Operation.INSTALLATION
        db_command.not_before = db_command.created_at
        db_command.time = db_command.created_at
        db_command.result_time = db_command.created_at
        db_command.status = DeviceCommand.Status.ACKNOWLEDGED
        db_command.save()
        db_command.refresh_from_db()
        self.assertEqual(
            db_command.serialize_for_event(),
            {"pk": db_command.pk,
             "uuid": str(cmd.uuid),
             "name": "DeviceLock",
             "artifact_version": av.serialize_for_event(),
             "artifact_operation": "Installation",
             "not_before": db_command.created_at,
             "time": db_command.created_at,
             "result_time": db_command.created_at,
             "status": "Acknowledged",
             "created_at": db_command.created_at,
             "updated_at": db_command.updated_at,
             "enrolled_device": self.enrolled_device.serialize_for_event(keys_only=True)}
        )
        self.assertEqual(
            db_command.serialize_for_event(keys_only=True),
            {"pk": db_command.pk, "uuid": str(cmd.uuid), "name": "DeviceLock"}
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
