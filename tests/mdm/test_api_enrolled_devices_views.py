import json
import plistlib
from datetime import datetime
from unittest.mock import patch

from accounts.models import APIToken, User
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from zentral.contrib.inventory.models import MachineTag, MetaBusinessUnit, Tag
from zentral.contrib.mdm.commands import SetAutoAdminPassword
from zentral.contrib.mdm.commands.base import load_command
from zentral.contrib.mdm.events import (
    AdminPasswordViewedEvent,
    DeviceLockPinViewedEvent,
    FileVaultPRKViewedEvent,
    RecoveryPasswordViewedEvent,
)
from zentral.contrib.mdm.models import Platform
from zentral.core.events.base import AuditEvent

from .utils import force_dep_enrollment_session, force_enrolled_user


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
            cls.mbu, authenticated=True, completed=True, realm_user=True, realm_user_email=cls.user.email
        )
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device
        cls.enrolled_user = force_enrolled_user(cls.enrolled_device)

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "mdm"

    # RequestCase implementation

    def _get_api_key(self):
        return self.api_key

    # Assertions

    def _assert_found_enrolled_device(self, response, last_ip=None, last_seen_at=None):
        if last_seen_at:
            last_seen_at = last_seen_at.isoformat()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'count': 1,
             'next': None,
             'previous': None,
             'results': [{'activation_lock_manageable': None,
                          'admin_guid': None,
                          'admin_password_escrowed': False,
                          'admin_shortname': None,
                          'apple_silicon': None,
                          'awaiting_configuration': None,
                          'blocked_at': None,
                          'blueprint': None,
                          'bootstrap_token_escrowed': False,
                          'build_version': '',
                          'cert_not_valid_after': self.enrolled_device.cert_not_valid_after.isoformat(),
                          'cert_att_serial_number': None,
                          'cert_att_udid': None,
                          'checkout_at': None,
                          'created_at': self.enrolled_device.created_at.isoformat(),
                          'declarative_management': False,
                          'dep_enrollment': None,
                          'filevault_enabled': None,
                          'filevault_prk_escrowed': False,
                          'id': self.enrolled_device.id,
                          'last_notified_at': None,
                          'last_ip': last_ip,
                          'last_seen_at': last_seen_at,
                          'model': None,
                          'name': None,
                          'os_version': '',
                          'platform': 'macOS',
                          'recovery_password_escrowed': False,
                          'serial_number': self.enrolled_device.serial_number,
                          'supervised': None,
                          'udid': self.enrolled_device.udid,
                          'updated_at': self.enrolled_device.updated_at.isoformat(),
                          'user_approved_enrollment': None,
                          'user_enrollment': None,
                          'realm_user': {
                              'pk': str(self.dep_enrollment_session.realm_user.pk),
                              'email': self.dep_enrollment_session.realm_user.email,
                              'username': self.dep_enrollment_session.realm_user.username
                          },
                          'users': [{
                              'id': self.enrolled_user.id,
                              'enrollment_id': None,
                              'user_id': self.enrolled_user.user_id,
                              'long_name': self.enrolled_user.long_name,
                              'short_name': self.enrolled_user.short_name,
                              'declarative_management': False,
                              'last_ip': last_ip,
                              'last_seen_at': last_seen_at,
                              'created_at': self.enrolled_user.created_at.isoformat(),
                              'updated_at': self.enrolled_user.updated_at.isoformat(),
                          }]}]}
        )

    # enrolled devices

    def test_enrolled_devices_unauthorized(self):
        response = self.get(reverse("mdm_api:enrolled_devices"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_enrolled_devices_permission_denied(self):
        response = self.get(reverse("mdm_api:enrolled_devices"))
        self.assertEqual(response.status_code, 403)

    def test_enrolled_devices_method_not_allowed(self):
        self.set_permissions("mdm.add_enrolleddevice")
        response = self.post(reverse("mdm_api:enrolled_devices"), {})
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.json(), {'detail': 'Method "POST" not allowed.'})

    def test_enrolled_devices_default_values(self):
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.get(reverse("mdm_api:enrolled_devices"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'count': 1,
             'next': None,
             'previous': None,
             'results': [{'activation_lock_manageable': None,
                          'admin_guid': None,
                          'admin_password_escrowed': False,
                          'admin_shortname': None,
                          'apple_silicon': None,
                          'awaiting_configuration': None,
                          'blocked_at': None,
                          'blueprint': None,
                          'bootstrap_token_escrowed': False,
                          'build_version': '',
                          'cert_not_valid_after': self.enrolled_device.cert_not_valid_after.isoformat(),
                          'cert_att_serial_number': None,
                          'cert_att_udid': None,
                          'checkout_at': None,
                          'created_at': self.enrolled_device.created_at.isoformat(),
                          'declarative_management': False,
                          'dep_enrollment': None,
                          'filevault_enabled': None,
                          'filevault_prk_escrowed': False,
                          'id': self.enrolled_device.id,
                          'last_notified_at': None,
                          'last_ip': None,
                          'last_seen_at': None,
                          'model': None,
                          'name': None,
                          'os_version': '',
                          'platform': 'macOS',
                          'recovery_password_escrowed': False,
                          'serial_number': self.enrolled_device.serial_number,
                          'supervised': None,
                          'udid': self.enrolled_device.udid,
                          'updated_at': self.enrolled_device.updated_at.isoformat(),
                          'user_approved_enrollment': None,
                          'user_enrollment': None,
                          'realm_user': {
                              'pk': str(self.dep_enrollment_session.realm_user.pk),
                              'email': self.dep_enrollment_session.realm_user.email,
                              'username': self.dep_enrollment_session.realm_user.username
                          },
                          'users': [{
                              'id': self.enrolled_user.id,
                              'enrollment_id': None,
                              'user_id': self.enrolled_user.user_id,
                              'long_name': self.enrolled_user.long_name,
                              'short_name': self.enrolled_user.short_name,
                              'declarative_management': False,
                              'last_ip': None,
                              'last_seen_at': None,
                              'created_at': self.enrolled_user.created_at.isoformat(),
                              'updated_at': self.enrolled_user.updated_at.isoformat(),
                          }]}]}
        )

    def test_enrolled_devices_by_serial_number(self):
        self.enrolled_device.last_ip = "54d0:a11d:dee1:88bf:a120:8ff2:da43:aaad"
        self.enrolled_device.last_seen_at = datetime(2025, 9, 25)
        self.enrolled_device.save()
        self.enrolled_user.last_ip = "54d0:a11d:dee1:88bf:a120:8ff2:da43:aaad"
        self.enrolled_user.last_seen_at = datetime(2025, 9, 25)
        self.enrolled_user.save()
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.get(
            reverse("mdm_api:enrolled_devices")
            + f"?serial_number={self.enrolled_device.serial_number}"
        )
        self._assert_found_enrolled_device(response, self.enrolled_user.last_ip, self.enrolled_user.last_seen_at)

    def test_enrolled_devices_by_serial_number_no_result(self):
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.get(
            reverse("mdm_api:enrolled_devices")
            + "?serial_number=yolofomo"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'count': 0, 'next': None, 'previous': None, 'results': []})

    def test_enrolled_devices_by_udid(self):
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.get(
            reverse("mdm_api:enrolled_devices")
            + f"?udid={self.enrolled_device.udid}"
        )
        self._assert_found_enrolled_device(response)

    def test_enrolled_devices_by_udid_no_result(self):
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.get(
            reverse("mdm_api:enrolled_devices")
            + "?udid=00000000-0000-0000-0000-000000000000"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'count': 0, 'next': None, 'previous': None, 'results': []})

    def test_enrolled_devices_with_secrets(self):
        self.enrolled_device.security_info = {"FDE_Enabled": True}
        self.enrolled_device.set_bootstrap_token(b"un")
        self.enrolled_device.set_filevault_prk("deux")
        self.enrolled_device.set_recovery_password("trois")
        self.enrolled_device.device_information = {
            "AutoSetupAdminAccounts": [
                {"GUID": "yolo", "shortName": "fomo"}
            ]
        }
        self.enrolled_device.set_admin_password("quatre")
        self.enrolled_device.save()
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.get(reverse("mdm_api:enrolled_devices"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'count': 1,
             'next': None,
             'previous': None,
             'results': [{'activation_lock_manageable': None,
                          'admin_guid': "yolo",
                          'admin_password_escrowed': True,
                          'admin_shortname': "fomo",
                          'apple_silicon': None,
                          'awaiting_configuration': None,
                          'blocked_at': None,
                          'blueprint': None,
                          'bootstrap_token_escrowed': True,
                          'build_version': '',
                          'cert_not_valid_after': self.enrolled_device.cert_not_valid_after.isoformat(),
                          'cert_att_serial_number': None,
                          'cert_att_udid': None,
                          'checkout_at': None,
                          'created_at': self.enrolled_device.created_at.isoformat(),
                          'declarative_management': False,
                          'dep_enrollment': None,
                          'filevault_enabled': True,
                          'filevault_prk_escrowed': True,
                          'id': self.enrolled_device.id,
                          'last_notified_at': None,
                          'last_ip': None,
                          'last_seen_at': None,
                          'model': None,
                          'name': None,
                          'os_version': '',
                          'platform': 'macOS',
                          'recovery_password_escrowed': True,
                          'serial_number': self.enrolled_device.serial_number,
                          'supervised': None,
                          'udid': self.enrolled_device.udid,
                          'updated_at': self.enrolled_device.updated_at.isoformat(),
                          'user_approved_enrollment': None,
                          'user_enrollment': None,
                          'realm_user': {
                              'pk': str(self.dep_enrollment_session.realm_user.pk),
                              'email': self.dep_enrollment_session.realm_user.email,
                              'username': self.dep_enrollment_session.realm_user.username
                          },
                          'users': [{
                              'id': self.enrolled_user.id,
                              'enrollment_id': None,
                              'user_id': self.enrolled_user.user_id,
                              'long_name': self.enrolled_user.long_name,
                              'short_name': self.enrolled_user.short_name,
                              'declarative_management': False,
                              'last_ip': None,
                              'last_seen_at': None,
                              'created_at': self.enrolled_user.created_at.isoformat(),
                              'updated_at': self.enrolled_user.updated_at.isoformat(),
                          }]}]}
        )

    def test_enrolled_devices_tag_filters_unknown(self):
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.get(
            reverse("mdm_api:enrolled_devices")
            + "?tags=0&excluded_tags=0"
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'excluded_tags': ['Select a valid choice. 0 is not one of the available choices.'],
             'tags': ['Select a valid choice. 0 is not one of the available choices.']}
        )

    def test_enrolled_devices_tag_filters_no_results(self):
        t = Tag.objects.create(name=get_random_string(12))
        et = Tag.objects.create(name=get_random_string(12))
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.get(
            reverse("mdm_api:enrolled_devices")
            + f"?tags={t.pk}&excluded_tags={et.pk}"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'count': 0, 'next': None, 'previous': None, 'results': []})

    def test_enrolled_devices_tag_filters_results(self):
        t = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number=self.enrolled_device.serial_number, tag=t)
        t2 = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number=self.enrolled_device.serial_number, tag=t2)
        et = Tag.objects.create(name=get_random_string(12))
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.get(
            reverse("mdm_api:enrolled_devices")
            + f"?tags={t.pk}&tags={t2.pk}&excluded_tags={et.pk}"
        )
        self._assert_found_enrolled_device(response, self.enrolled_user.last_ip, self.enrolled_user.last_seen_at)

    def test_enrolled_devices_excluded_tag_filter_no_results(self):
        t = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number=self.enrolled_device.serial_number, tag=t)
        t2 = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number=self.enrolled_device.serial_number, tag=t2)
        et = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number=self.enrolled_device.serial_number, tag=et)
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.get(
            reverse("mdm_api:enrolled_devices")
            + f"?tags={t.pk}&tags={t2.pk}&excluded_tags={et.pk}"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'count': 0, 'next': None, 'previous': None, 'results': []})

    def test_enrolled_devices_by_short_name(self):
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.get(
            reverse("mdm_api:enrolled_devices")
            + f"?short_name={self.enrolled_user.short_name}"
        )
        self._assert_found_enrolled_device(response, self.enrolled_user.last_ip, self.enrolled_user.last_seen_at)

    def test_enrolled_devices_by_short_name_empty_value(self):
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.get(
            reverse("mdm_api:enrolled_devices")
            + "?short_name="
        )
        self._assert_found_enrolled_device(response, self.enrolled_user.last_ip, self.enrolled_user.last_seen_at)

    def test_enrolled_devices_by_short_name_no_result(self):
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.get(
            reverse("mdm_api:enrolled_devices")
            + "?short_name=johndoe"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'count': 0, 'next': None, 'previous': None, 'results': []})

    def test_enrolled_devices_by_user_email(self):
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.get(
            reverse("mdm_api:enrolled_devices")
            + f"?email={self.user.email}"
        )
        self._assert_found_enrolled_device(response, self.enrolled_user.last_ip, self.enrolled_user.last_seen_at)

        new_user_email = f"new_{get_random_string(12)}@zentral.com"
        session, _, _ = force_dep_enrollment_session(
            self.mbu,
            realm_user=True,
            realm_user_email=new_user_email,
            serial_number=self.enrolled_device.serial_number,
            device_udid=str(self.enrolled_device.udid),
            authenticated=False,
            completed=False,
        )
        session.set_authenticated_status(self.enrolled_device)
        session.set_completed_status(self.enrolled_device)

        response = self.get(
            reverse("mdm_api:enrolled_devices")
            + f"?email={self.user.email}"
        )
        self.assertEqual(response.json()["count"], 0)
        response = self.get(
            reverse("mdm_api:enrolled_devices")
            + f"?email={new_user_email}"
        )
        payload = response.json()
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["results"][0]["serial_number"], self.enrolled_device.serial_number)

    def test_enrolled_devices_by_user_email_empty_value(self):
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.get(
            reverse("mdm_api:enrolled_devices")
            + "?email="
        )
        self._assert_found_enrolled_device(response, self.enrolled_user.last_ip, self.enrolled_user.last_seen_at)

    def test_enrolled_devices_by_user_email_no_result(self):
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.get(
            reverse("mdm_api:enrolled_devices")
            + "?email=no-reply@zentral.com"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'count': 0, 'next': None, 'previous': None, 'results': []})

    # block enrolled device

    def test_block_enrolled_device_unauthorized(self):
        response = self.post(reverse("mdm_api:block_enrolled_device", args=(self.enrolled_device.pk,)), None,
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_block_enrolled_device_permission_denied(self):
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.post(reverse("mdm_api:block_enrolled_device", args=(self.enrolled_device.pk,)), None)
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_block_enrolled_device_already_blocked(self, post_event):
        self.enrolled_device.block()
        self.set_permissions("mdm.change_enrolleddevice")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:block_enrolled_device", args=(self.enrolled_device.pk,)), None)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"detail": "Device already blocked."})
        self.assertEqual(len(callbacks), 0)
        post_event.assert_not_called()

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.contrib.mdm.api_views.enrolled_devices.send_enrolled_device_notification")
    def test_block_enrolled_device_audit_event(self, send_enrolled_device_notification, post_event):
        self.enrolled_device.unblock()
        self.set_permissions("mdm.change_enrolleddevice")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:block_enrolled_device", args=(self.enrolled_device.pk,)),
                                 None, ip="1.2.3.4")
        self.assertEqual(response.status_code, 200)
        # the push notification and the audit event
        self.assertEqual(len(callbacks), 2)
        send_enrolled_device_notification.assert_called_once()
        self.assertEqual(send_enrolled_device_notification.call_args.args, (self.enrolled_device,))
        # the operator request travels with the notification, so its event is attributable
        self.assertEqual(send_enrolled_device_notification.call_args.kwargs["request"].method, "POST")
        self.enrolled_device.refresh_from_db()
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(event.payload["action"], "updated")
        self.assertEqual(event.payload["object"]["model"], "mdm.enrolleddevice")
        self.assertIsNone(event.payload["object"]["prev_value"]["blocked_at"])
        self.assertEqual(
            event.payload["object"]["new_value"]["blocked_at"],
            self.enrolled_device.blocked_at.isoformat()
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["machine_serial_number"], self.enrolled_device.serial_number)
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        request = metadata["request"]
        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["ip"], "1.2.3.4")
        self.assertEqual(request["view"], "mdm_api:block_enrolled_device")
        self.assertTrue(request["user"]["session"]["token_authenticated"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.contrib.mdm.api_views.enrolled_devices.send_enrolled_device_notification")
    def test_unblock_enrolled_device_audit_event(self, send_enrolled_device_notification, post_event):
        self.enrolled_device.block()
        blocked_at = self.enrolled_device.blocked_at
        self.set_permissions("mdm.change_enrolleddevice")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:unblock_enrolled_device", args=(self.enrolled_device.pk,)), None)
        self.assertEqual(response.status_code, 200)
        # only the audit event: a blocked device cannot be pinged
        self.assertEqual(len(callbacks), 1)
        send_enrolled_device_notification.assert_not_called()
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(event.payload["action"], "updated")
        self.assertEqual(event.payload["object"]["prev_value"]["blocked_at"], blocked_at.isoformat())
        self.assertIsNone(event.payload["object"]["new_value"]["blocked_at"])
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["machine_serial_number"], self.enrolled_device.serial_number)
        self.assertEqual(metadata["request"]["view"], "mdm_api:unblock_enrolled_device")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_unblock_enrolled_device_not_blocked_posts_no_event(self, post_event):
        self.enrolled_device.unblock()
        self.set_permissions("mdm.change_enrolleddevice")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:unblock_enrolled_device", args=(self.enrolled_device.pk,)), None)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(len(callbacks), 0)
        post_event.assert_not_called()

    def test_block_enrolled_device(self):
        self.enrolled_device.unblock()
        self.set_permissions("mdm.change_enrolleddevice")
        response = self.post(reverse("mdm_api:block_enrolled_device", args=(self.enrolled_device.pk,)), None)
        self.assertEqual(response.status_code, 200)
        self.enrolled_device.refresh_from_db()
        self.assertEqual(
            response.json(),
            {'activation_lock_manageable': None,
             'admin_guid': None,
             'admin_password_escrowed': False,
             'admin_shortname': None,
             'apple_silicon': None,
             'awaiting_configuration': None,
             'blocked_at': self.enrolled_device.blocked_at.isoformat(),
             'blueprint': None,
             'bootstrap_token_escrowed': False,
             'build_version': '',
             'cert_not_valid_after': self.enrolled_device.cert_not_valid_after.isoformat(),
             'cert_att_serial_number': None,
             'cert_att_udid': None,
             'checkout_at': None,
             'created_at': self.enrolled_device.created_at.isoformat(),
             'declarative_management': False,
             'dep_enrollment': None,
             'filevault_enabled': None,
             'filevault_prk_escrowed': False,
             'id': self.enrolled_device.pk,
             'last_notified_at': None,
             'last_ip': None,
             'last_seen_at': None,
             'model': None,
             'name': None,
             'os_version': '',
             'platform': 'macOS',
             'recovery_password_escrowed': False,
             'serial_number': self.enrolled_device.serial_number,
             'supervised': None,
             'udid': self.enrolled_device.udid,
             'updated_at': self.enrolled_device.updated_at.isoformat(),
             'user_approved_enrollment': None,
             'user_enrollment': None,
             'realm_user': None,
             'users': [{
                 'id': self.enrolled_user.id,
                 'enrollment_id': None,
                 'user_id': self.enrolled_user.user_id,
                 'long_name': self.enrolled_user.long_name,
                 'short_name': self.enrolled_user.short_name,
                 'declarative_management': False,
                 'last_ip': None,
                 'last_seen_at': None,
                 'created_at': self.enrolled_user.created_at.isoformat(),
                 'updated_at': self.enrolled_user.updated_at.isoformat(),
             }]}
        )

    # unblock enrolled device

    def test_unblock_enrolled_device_unauthorized(self):
        response = self.post(reverse("mdm_api:unblock_enrolled_device", args=(self.enrolled_device.pk,)), None,
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_unblock_enrolled_device_permission_denied(self):
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.post(reverse("mdm_api:unblock_enrolled_device", args=(self.enrolled_device.pk,)), None)
        self.assertEqual(response.status_code, 403)

    def test_unblock_enrolled_device_already_unblocked(self):
        self.enrolled_device.unblock()
        self.set_permissions("mdm.change_enrolleddevice")
        response = self.post(reverse("mdm_api:unblock_enrolled_device", args=(self.enrolled_device.pk,)), None)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"detail": "Device not blocked."})

    def test_unblock_enrolled_device(self):
        self.enrolled_device.block()
        self.set_permissions("mdm.change_enrolleddevice")
        response = self.post(reverse("mdm_api:unblock_enrolled_device", args=(self.enrolled_device.pk,)), None)
        self.assertEqual(response.status_code, 200)
        self.enrolled_device.refresh_from_db()
        self.assertEqual(
            response.json(),
            {'activation_lock_manageable': None,
             'admin_guid': None,
             'admin_password_escrowed': False,
             'admin_shortname': None,
             'apple_silicon': None,
             'awaiting_configuration': None,
             'blocked_at': None,
             'blueprint': None,
             'bootstrap_token_escrowed': False,
             'build_version': '',
             'cert_not_valid_after': self.enrolled_device.cert_not_valid_after.isoformat(),
             'cert_att_serial_number': None,
             'cert_att_udid': None,
             'checkout_at': None,
             'created_at': self.enrolled_device.created_at.isoformat(),
             'declarative_management': False,
             'dep_enrollment': None,
             'filevault_enabled': None,
             'filevault_prk_escrowed': False,
             'id': self.enrolled_device.pk,
             'last_notified_at': None,
             'last_ip': None,
             'last_seen_at': None,
             'model': None,
             'name': None,
             'os_version': '',
             'platform': 'macOS',
             'recovery_password_escrowed': False,
             'serial_number': self.enrolled_device.serial_number,
             'supervised': None,
             'udid': self.enrolled_device.udid,
             'updated_at': self.enrolled_device.updated_at.isoformat(),
             'user_approved_enrollment': None,
             'user_enrollment': None,
             'realm_user': None,
             'users': [{
                 'id': self.enrolled_user.id,
                 'enrollment_id': None,
                 'user_id': self.enrolled_user.user_id,
                 'long_name': self.enrolled_user.long_name,
                 'short_name': self.enrolled_user.short_name,
                 'declarative_management': False,
                 'last_ip': None,
                 'last_seen_at': None,
                 'created_at': self.enrolled_user.created_at.isoformat(),
                 'updated_at': self.enrolled_user.updated_at.isoformat(),
             }]}
        )

    # erase enrolled device

    def test_erase_enrolled_device_unauthorized(self):
        response = self.post(reverse("mdm_api:erase_enrolled_device", args=(self.enrolled_device.pk,)), {},
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_erase_enrolled_device_permission_denied(self):
        self.set_permissions("mdm.view_devicecommand")
        response = self.post(reverse("mdm_api:erase_enrolled_device", args=(self.enrolled_device.pk,)), {})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.mdm.api_views.enrolled_devices.EraseDevice.verify_target")
    def test_erase_enrolled_device_invalid_target(self, verify_target):
        # it should never happen, but we need to test this code path
        verify_target.return_value = False
        self.set_permissions("mdm.add_devicecommand")
        response = self.post(reverse("mdm_api:erase_enrolled_device", args=(self.enrolled_device.pk,)), {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'detail': 'Invalid target.'})

    def test_erase_enrolled_device_apple_silicon(self):
        self.enrolled_device.apple_silicon = True
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.enrolled_device.save()
        self.set_permissions("mdm.add_devicecommand")
        self.assertEqual(self.enrolled_device.commands.count(), 0)
        response = self.post(reverse("mdm_api:erase_enrolled_device", args=(self.enrolled_device.pk,)), {})
        self.assertEqual(self.enrolled_device.commands.count(), 1)
        db_command = self.enrolled_device.commands.first()
        self.assertEqual(
            response.json(),
            {'artifact_operation': None,
             'artifact_version': None,
             'created_at': db_command.created_at.isoformat(),
             'enrolled_device': self.enrolled_device.pk,
             'error_chain': None,
             'name': 'EraseDevice',
             'not_before': None,
             'result': None,
             'result_time': None,
             'status': None,
             'time': None,
             'updated_at': db_command.updated_at.isoformat(),
             'uuid': str(db_command.uuid)}
        )
        response = load_command(db_command).build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(
            payload,
            {"RequestType": "EraseDevice"}
        )

    def test_erase_enrolled_device_t1_missing_pin(self):
        self.set_permissions("mdm.add_devicecommand")
        response = self.post(reverse("mdm_api:erase_enrolled_device", args=(self.enrolled_device.pk,)), {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'pin': ['This field is required.']})

    def test_erase_enrolled_device_t1_bad_pin(self):
        self.set_permissions("mdm.add_devicecommand")
        response = self.post(reverse("mdm_api:erase_enrolled_device", args=(self.enrolled_device.pk,)),
                             {"pin": "!)="})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'pin': ['This value does not match the required pattern.']})

    def test_erase_enrolled_device_t1(self):
        self.assertFalse(self.enrolled_device.apple_silicon)
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.set_permissions("mdm.add_devicecommand")
        self.assertEqual(self.enrolled_device.commands.count(), 0)
        response = self.post(reverse("mdm_api:erase_enrolled_device", args=(self.enrolled_device.pk,)),
                             {"pin": "0123456"})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(self.enrolled_device.commands.count(), 1)
        db_command = self.enrolled_device.commands.first()
        self.assertEqual(
            response.json(),
            {'artifact_operation': None,
             'artifact_version': None,
             'created_at': db_command.created_at.isoformat(),
             'enrolled_device': self.enrolled_device.pk,
             'error_chain': None,
             'name': 'EraseDevice',
             'not_before': None,
             'result': None,
             'result_time': None,
             'status': None,
             'time': None,
             'updated_at': db_command.updated_at.isoformat(),
             'uuid': str(db_command.uuid)}
        )
        response = load_command(db_command).build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(
            payload,
            {"RequestType": "EraseDevice",
             "PIN": "0123456"}
        )

    def test_erase_enrolled_device_ios_missing_fields(self):
        self.enrolled_device.platform = Platform.IOS
        self.enrolled_device.save()
        self.set_permissions("mdm.add_devicecommand")
        response = self.post(reverse("mdm_api:erase_enrolled_device", args=(self.enrolled_device.pk,)), {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'disallow_proximity_setup': ['This field is required.'],
                                           'preserve_data_plan': ['This field is required.']})

    def test_erase_enrolled_device_ios(self):
        self.assertFalse(self.enrolled_device.apple_silicon)
        self.enrolled_device.platform = Platform.IOS
        self.enrolled_device.save()
        self.set_permissions("mdm.add_devicecommand")
        self.assertEqual(self.enrolled_device.commands.count(), 0)
        response = self.post(reverse("mdm_api:erase_enrolled_device", args=(self.enrolled_device.pk,)),
                             {"disallow_proximity_setup": True,
                              "preserve_data_plan": True})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(self.enrolled_device.commands.count(), 1)
        db_command = self.enrolled_device.commands.first()
        self.assertEqual(
            response.json(),
            {'artifact_operation': None,
             'artifact_version': None,
             'created_at': db_command.created_at.isoformat(),
             'enrolled_device': self.enrolled_device.pk,
             'error_chain': None,
             'name': 'EraseDevice',
             'not_before': None,
             'result': None,
             'result_time': None,
             'status': None,
             'time': None,
             'updated_at': db_command.updated_at.isoformat(),
             'uuid': str(db_command.uuid)}
        )
        response = load_command(db_command).build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(
            payload,
            {"RequestType": "EraseDevice",
             "DisallowProximitySetup": True,
             "PreserveDataPlan": True}
        )

    # lock enrolled device

    def test_lock_enrolled_device_unauthorized(self):
        response = self.post(reverse("mdm_api:lock_enrolled_device", args=(self.enrolled_device.pk,)), {},
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_lock_enrolled_device_permission_denied(self):
        self.set_permissions("mdm.view_devicecommand")
        response = self.post(reverse("mdm_api:lock_enrolled_device", args=(self.enrolled_device.pk,)), {})
        self.assertEqual(response.status_code, 403)

    def test_lock_enrolled_device_invalid_target(self):
        self.enrolled_device.user_enrollment = True  # lock not possible on user enrolled macOS devices
        self.enrolled_device.save()
        self.set_permissions("mdm.add_devicecommand")
        response = self.post(reverse("mdm_api:lock_enrolled_device", args=(self.enrolled_device.pk,)), {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'detail': 'Invalid target.'})

    def test_lock_enrolled_device_macos_missing_pin(self):
        self.set_permissions("mdm.add_devicecommand")
        response = self.post(reverse("mdm_api:lock_enrolled_device", args=(self.enrolled_device.pk,)), {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'pin': ['This field is required.']})

    def test_lock_enrolled_device_macos_bad_pin(self):
        self.set_permissions("mdm.add_devicecommand")
        response = self.post(reverse("mdm_api:lock_enrolled_device", args=(self.enrolled_device.pk,)),
                             {"pin": "!)="})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'pin': ['This value does not match the required pattern.']})

    def test_lock_enrolled_device_macos(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.set_permissions("mdm.add_devicecommand")
        self.assertEqual(self.enrolled_device.commands.count(), 0)
        response = self.post(reverse("mdm_api:lock_enrolled_device", args=(self.enrolled_device.pk,)),
                             {"pin": "012345"})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(self.enrolled_device.commands.count(), 1)
        db_command = self.enrolled_device.commands.first()
        self.assertEqual(
            response.json(),
            {'artifact_operation': None,
             'artifact_version': None,
             'created_at': db_command.created_at.isoformat(),
             'enrolled_device': self.enrolled_device.pk,
             'error_chain': None,
             'name': 'DeviceLock',
             'not_before': None,
             'result': None,
             'result_time': None,
             'status': None,
             'time': None,
             'updated_at': db_command.updated_at.isoformat(),
             'uuid': str(db_command.uuid)}
        )
        response = load_command(db_command).build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(
            payload,
            {"RequestType": "DeviceLock",
             "PIN": "012345"}
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_lock_enrolled_device_audit_event(self, post_event):
        self.set_permissions("mdm.add_devicecommand")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:lock_enrolled_device", args=(self.enrolled_device.pk,)),
                                 {"pin": "012345", "message": "lost mac"}, ip="1.2.3.4")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        db_command = self.enrolled_device.commands.first()
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(event.payload["action"], "created")
        self.assertEqual(event.payload["object"]["model"], "mdm.devicecommand")
        self.assertEqual(event.payload["object"]["pk"], str(db_command.pk))
        new_value = event.payload["object"]["new_value"]
        self.assertEqual(new_value["name"], "DeviceLock")
        self.assertEqual(new_value["kwargs"], {"Message": "lost mac", "PIN": "<redacted>"})
        # the PIN reaches the device but never the audit trail
        self.assertNotIn("012345", json.dumps(event.payload))
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["machine_serial_number"], self.enrolled_device.serial_number)
        self.assertEqual(metadata["objects"], {"mdm_device_command": [str(db_command.uuid)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        request = metadata["request"]
        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["ip"], "1.2.3.4")
        self.assertEqual(request["view"], "mdm_api:lock_enrolled_device")
        self.assertEqual(
            request["path"],
            reverse("mdm_api:lock_enrolled_device", args=(self.enrolled_device.pk,))
        )
        self.assertEqual(request["user"]["username"], self.service_account.username)
        self.assertTrue(request["user"]["session"]["token_authenticated"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_erase_enrolled_device_audit_event(self, post_event):
        self.set_permissions("mdm.add_devicecommand")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:erase_enrolled_device", args=(self.enrolled_device.pk,)),
                                 {"pin": "012345"})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        new_value = event.payload["object"]["new_value"]
        self.assertEqual(new_value["name"], "EraseDevice")
        self.assertEqual(new_value["kwargs"], {"PIN": "<redacted>"})
        self.assertNotIn("012345", json.dumps(event.payload))

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_send_custom_enrolled_device_command_audit_event(self, post_event):
        self.set_permissions("mdm.add_devicecommand")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:send_custom_enrolled_device_command", args=(self.enrolled_device.pk,)),
                {"command": plistlib.dumps({"RequestType": "ClearPasscode",
                                            "UnlockToken": "s3cr3t-token"}).decode("utf-8")}
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        new_value = event.payload["object"]["new_value"]
        self.assertEqual(new_value["name"], "CustomCommand")
        # only the shape of the operator supplied payload is audited
        self.assertEqual(
            new_value["kwargs"],
            {"command": {"RequestType": "ClearPasscode", "keys": ["UnlockToken"]}}
        )
        self.assertNotIn("s3cr3t-token", json.dumps(event.payload))

    def test_lock_enrolled_device_ios_default(self):
        self.enrolled_device.platform = Platform.IOS
        self.enrolled_device.save()
        self.set_permissions("mdm.add_devicecommand")
        self.assertEqual(self.enrolled_device.commands.count(), 0)
        response = self.post(reverse("mdm_api:lock_enrolled_device", args=(self.enrolled_device.pk,)), {})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(self.enrolled_device.commands.count(), 1)
        db_command = self.enrolled_device.commands.first()
        self.assertEqual(
            response.json(),
            {'artifact_operation': None,
             'artifact_version': None,
             'created_at': db_command.created_at.isoformat(),
             'enrolled_device': self.enrolled_device.pk,
             'error_chain': None,
             'name': 'DeviceLock',
             'not_before': None,
             'result': None,
             'result_time': None,
             'status': None,
             'time': None,
             'updated_at': db_command.updated_at.isoformat(),
             'uuid': str(db_command.uuid)}
        )
        response = load_command(db_command).build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(
            payload,
            {"RequestType": "DeviceLock"}
        )

    def test_lock_enrolled_device_ios_full(self):
        self.enrolled_device.platform = Platform.IOS
        self.enrolled_device.save()
        self.set_permissions("mdm.add_devicecommand")
        self.assertEqual(self.enrolled_device.commands.count(), 0)
        response = self.post(reverse("mdm_api:lock_enrolled_device", args=(self.enrolled_device.pk,)),
                             {"message": "Yolo",
                              "phone_number": "123"})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(self.enrolled_device.commands.count(), 1)
        db_command = self.enrolled_device.commands.first()
        self.assertEqual(
            response.json(),
            {'artifact_operation': None,
             'artifact_version': None,
             'created_at': db_command.created_at.isoformat(),
             'enrolled_device': self.enrolled_device.pk,
             'error_chain': None,
             'name': 'DeviceLock',
             'not_before': None,
             'result': None,
             'result_time': None,
             'status': None,
             'time': None,
             'updated_at': db_command.updated_at.isoformat(),
             'uuid': str(db_command.uuid)}
        )
        response = load_command(db_command).build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(
            payload,
            {"RequestType": "DeviceLock",
             "Message": "Yolo",
             "PhoneNumber": "123"}
        )

    # send custom enrolled device command

    def test_send_custom_enrolled_device_command_unauthorized(self):
        response = self.post(reverse("mdm_api:send_custom_enrolled_device_command", args=(self.enrolled_device.pk,)),
                             {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_send_custom_enrolled_device_command_permission_denied(self):
        self.set_permissions("mdm.view_devicecommand")
        response = self.post(reverse("mdm_api:send_custom_enrolled_device_command", args=(self.enrolled_device.pk,)),
                             {})
        self.assertEqual(response.status_code, 403)

    def test_send_custom_enrolled_device_command_required_fields(self):
        self.set_permissions("mdm.add_devicecommand")
        response = self.post(reverse("mdm_api:send_custom_enrolled_device_command", args=(self.enrolled_device.pk,)),
                             {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'command': ['This field is required.']})

    def test_send_custom_enrolled_device_command_empty_command(self):
        self.set_permissions("mdm.add_devicecommand")
        response = self.post(reverse("mdm_api:send_custom_enrolled_device_command", args=(self.enrolled_device.pk,)),
                             {"command": ""})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'command': ['This field may not be blank.']})

    def test_send_custom_enrolled_device_command_invalid_plist(self):
        self.set_permissions("mdm.add_devicecommand")
        response = self.post(reverse("mdm_api:send_custom_enrolled_device_command", args=(self.enrolled_device.pk,)),
                             {"command": "abc"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'command': ['Invalid property list']})

    def test_send_custom_enrolled_device_command_not_a_dict(self):
        self.set_permissions("mdm.add_devicecommand")
        response = self.post(reverse("mdm_api:send_custom_enrolled_device_command", args=(self.enrolled_device.pk,)),
                             {"command": plistlib.dumps([1]).decode("utf-8")})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'command': ['Not a dictionary']})

    def test_send_custom_enrolled_device_command_missing_request_type(self):
        self.set_permissions("mdm.add_devicecommand")
        response = self.post(reverse("mdm_api:send_custom_enrolled_device_command", args=(self.enrolled_device.pk,)),
                             {"command": plistlib.dumps({}).decode("utf-8")})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'command': ['Missing or empty RequestType']})

    def test_send_custom_enrolled_device_command(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.set_permissions("mdm.add_devicecommand")
        self.assertEqual(self.enrolled_device.commands.count(), 0)
        response = self.post(reverse("mdm_api:send_custom_enrolled_device_command", args=(self.enrolled_device.pk,)),
                             {"command": plistlib.dumps({"RequestType": "EnableRemoteDesktop"}).decode("utf-8")})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(self.enrolled_device.commands.count(), 1)
        db_command = self.enrolled_device.commands.first()
        self.assertEqual(
            response.json(),
            {'artifact_operation': None,
             'artifact_version': None,
             'created_at': db_command.created_at.isoformat(),
             'enrolled_device': self.enrolled_device.pk,
             'error_chain': None,
             'name': 'CustomCommand',
             'not_before': None,
             'result': None,
             'result_time': None,
             'status': None,
             'time': None,
             'updated_at': db_command.updated_at.isoformat(),
             'uuid': str(db_command.uuid)}
        )
        response = load_command(db_command).build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(
            payload,
            {"RequestType": "EnableRemoteDesktop"},
        )

    # enrolled device filevault prk

    def test_enrolled_device_filevault_prk_unauthorized(self):
        response = self.get(reverse("mdm_api:enrolled_device_filevault_prk", args=(self.enrolled_device.pk,)),
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_enrolled_device_filevault_prk_permission_denied(self):
        response = self.get(reverse("mdm_api:enrolled_device_filevault_prk", args=(self.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_enrolled_device_filevault_prk_login_permission_denied(self):
        self.login()
        response = self.get(reverse("mdm_api:enrolled_device_filevault_prk", args=(self.enrolled_device.pk,)),
                            include_token=False)
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enrolled_device_filevault_prk_null(self, post_event):
        self.set_permissions("mdm.view_filevault_prk")
        response = self.get(reverse("mdm_api:enrolled_device_filevault_prk", args=(self.enrolled_device.pk,)))
        self.assertEqual(
            response.json(),
            {"id": self.enrolled_device.pk,
             "serial_number": self.enrolled_device.serial_number,
             "filevault_prk": None}
        )
        post_event.assert_not_called()

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enrolled_device_filevault_prk(self, post_event):
        self.enrolled_device.set_filevault_prk("123456")
        self.enrolled_device.save()
        self.set_permissions("mdm.view_filevault_prk")
        response = self.get(reverse("mdm_api:enrolled_device_filevault_prk", args=(self.enrolled_device.pk,)))
        self.assertEqual(
            response.json(),
            {"id": self.enrolled_device.pk,
             "serial_number": self.enrolled_device.serial_number,
             "filevault_prk": "123456"}
        )
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, FileVaultPRKViewedEvent)
        self.assertEqual(event.metadata.machine_serial_number, self.enrolled_device.serial_number)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enrolled_device_filevault_prk_login(self, post_event):
        self.enrolled_device.set_filevault_prk("123456")
        self.enrolled_device.save()
        self.login("mdm.view_filevault_prk")
        response = self.get(reverse("mdm_api:enrolled_device_filevault_prk", args=(self.enrolled_device.pk,)),
                            include_token=False)
        self.assertEqual(
            response.json(),
            {"id": self.enrolled_device.pk,
             "serial_number": self.enrolled_device.serial_number,
             "filevault_prk": "123456"}
        )
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, FileVaultPRKViewedEvent)
        self.assertEqual(event.metadata.machine_serial_number, self.enrolled_device.serial_number)

    # enrolled device recovery password

    def test_enrolled_device_recovery_password_unauthorized(self):
        response = self.get(reverse("mdm_api:enrolled_device_recovery_password", args=(self.enrolled_device.pk,)),
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_enrolled_device_recovery_password_permission_denied(self):
        response = self.get(reverse("mdm_api:enrolled_device_recovery_password", args=(self.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_enrolled_device_recovery_password_login_permission_denied(self):
        self.login()
        response = self.get(reverse("mdm_api:enrolled_device_recovery_password", args=(self.enrolled_device.pk,)),
                            include_token=False)
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enrolled_device_recovery_password_null(self, post_event):
        self.set_permissions("mdm.view_recovery_password")
        response = self.get(reverse("mdm_api:enrolled_device_recovery_password", args=(self.enrolled_device.pk,)))
        self.assertEqual(
            response.json(),
            {"id": self.enrolled_device.pk,
             "serial_number": self.enrolled_device.serial_number,
             "recovery_password": None}
        )
        post_event.assert_not_called()

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enrolled_device_recovery_password(self, post_event):
        self.enrolled_device.set_recovery_password("123456")
        self.enrolled_device.save()
        self.set_permissions("mdm.view_recovery_password")
        response = self.get(reverse("mdm_api:enrolled_device_recovery_password", args=(self.enrolled_device.pk,)))
        self.assertEqual(
            response.json(),
            {"id": self.enrolled_device.pk,
             "serial_number": self.enrolled_device.serial_number,
             "recovery_password": "123456"}
        )
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, RecoveryPasswordViewedEvent)
        self.assertEqual(event.metadata.machine_serial_number, self.enrolled_device.serial_number)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enrolled_device_recovery_password_login(self, post_event):
        self.enrolled_device.set_recovery_password("123456")
        self.enrolled_device.save()
        self.login("mdm.view_recovery_password")
        response = self.get(reverse("mdm_api:enrolled_device_recovery_password", args=(self.enrolled_device.pk,)),
                            include_token=False)
        self.assertEqual(
            response.json(),
            {"id": self.enrolled_device.pk,
             "serial_number": self.enrolled_device.serial_number,
             "recovery_password": "123456"}
        )
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, RecoveryPasswordViewedEvent)
        self.assertEqual(event.metadata.machine_serial_number, self.enrolled_device.serial_number)

    # enrolled device admin password

    def test_enrolled_device_admin_password_unauthorized(self):
        response = self.get(reverse("mdm_api:enrolled_device_admin_password", args=(self.enrolled_device.pk,)),
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_enrolled_device_admin_password_permission_denied(self):
        response = self.get(reverse("mdm_api:enrolled_device_admin_password", args=(self.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_enrolled_device_admin_password_login_permission_denied(self):
        self.login()
        response = self.get(reverse("mdm_api:enrolled_device_admin_password", args=(self.enrolled_device.pk,)),
                            include_token=False)
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enrolled_device_admin_password_null(self, post_event):
        self.set_permissions("mdm.view_admin_password")
        response = self.get(reverse("mdm_api:enrolled_device_admin_password", args=(self.enrolled_device.pk,)))
        self.assertEqual(
            response.json(),
            {"id": self.enrolled_device.pk,
             "serial_number": self.enrolled_device.serial_number,
             "admin_password": None}
        )
        post_event.assert_not_called()

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enrolled_device_admin_password(self, post_event):
        self.assertEqual(self.dep_enrollment_session.dep_enrollment.admin_password_rotation_delay, 60)
        self.enrolled_device.set_admin_password("123456")
        self.enrolled_device.device_information = {
            "AutoSetupAdminAccounts": [
                {"GUID": "yolo", "shortName": "fomo"}
            ]
        }
        self.enrolled_device.save()
        self.set_permissions("mdm.view_admin_password")
        response = self.get(reverse("mdm_api:enrolled_device_admin_password", args=(self.enrolled_device.pk,)))
        self.assertEqual(
            response.json(),
            {"id": self.enrolled_device.pk,
             "serial_number": self.enrolled_device.serial_number,
             "admin_password": "123456"}
        )
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AdminPasswordViewedEvent)
        self.assertEqual(event.metadata.machine_serial_number, self.enrolled_device.serial_number)
        command_qs = self.enrolled_device.commands.all()
        self.assertEqual(command_qs.count(), 1)
        command = load_command(command_qs.first())
        self.assertIsInstance(command, SetAutoAdminPassword)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enrolled_device_admin_password_login(self, post_event):
        self.assertEqual(self.dep_enrollment_session.dep_enrollment.admin_password_rotation_delay, 60)
        self.enrolled_device.set_admin_password("123456")
        self.enrolled_device.device_information = {
            "AutoSetupAdminAccounts": [
                {"GUID": "yolo", "shortName": "fomo"}
            ]
        }
        self.enrolled_device.save()
        self.login("mdm.view_admin_password")
        response = self.get(reverse("mdm_api:enrolled_device_admin_password", args=(self.enrolled_device.pk,)),
                            include_token=False)
        self.assertEqual(
            response.json(),
            {"id": self.enrolled_device.pk,
             "serial_number": self.enrolled_device.serial_number,
             "admin_password": "123456"}
        )
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AdminPasswordViewedEvent)
        self.assertEqual(event.metadata.machine_serial_number, self.enrolled_device.serial_number)
        command_qs = self.enrolled_device.commands.all()
        self.assertEqual(command_qs.count(), 1)
        command = load_command(command_qs.first())
        self.assertIsInstance(command, SetAutoAdminPassword)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enrolled_device_admin_password_login_no_auto_rotation(self, post_event):
        self.dep_enrollment_session.dep_enrollment.admin_password_rotation_delay = 0  # no auto rotation
        self.dep_enrollment_session.dep_enrollment.save()
        self.enrolled_device.set_admin_password("123456")
        self.enrolled_device.device_information = {
            "AutoSetupAdminAccounts": [
                {"GUID": "yolo", "shortName": "fomo"}
            ]
        }
        self.enrolled_device.save()
        self.login("mdm.view_admin_password")
        response = self.get(reverse("mdm_api:enrolled_device_admin_password", args=(self.enrolled_device.pk,)),
                            include_token=False)
        self.assertEqual(
            response.json(),
            {"id": self.enrolled_device.pk,
             "serial_number": self.enrolled_device.serial_number,
             "admin_password": "123456"}
        )
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AdminPasswordViewedEvent)
        self.assertEqual(event.metadata.machine_serial_number, self.enrolled_device.serial_number)
        command_qs = self.enrolled_device.commands.all()
        self.assertEqual(command_qs.count(), 0)

    # enrolled device device log pin

    def test_enrolled_device_device_lock_pin_unauthorized(self):
        response = self.get(reverse("mdm_api:enrolled_device_device_lock_pin", args=(self.enrolled_device.pk,)),
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_enrolled_device_device_lock_pin_permission_denied(self):
        response = self.get(reverse("mdm_api:enrolled_device_device_lock_pin", args=(self.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_enrolled_device_device_lock_pin_login_permission_denied(self):
        self.login()
        response = self.get(reverse("mdm_api:enrolled_device_device_lock_pin", args=(self.enrolled_device.pk,)),
                            include_token=False)
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enrolled_device_device_lock_pin_null(self, post_event):
        self.set_permissions("mdm.view_device_lock_pin")
        response = self.get(reverse("mdm_api:enrolled_device_device_lock_pin", args=(self.enrolled_device.pk,)))
        self.assertEqual(
            response.json(),
            {"id": self.enrolled_device.pk,
             "serial_number": self.enrolled_device.serial_number,
             "device_lock_pin": None}
        )
        post_event.assert_not_called()

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enrolled_device_device_lock_pin(self, post_event):
        self.enrolled_device.platform = Platform.MACOS
        self.enrolled_device.set_device_lock_pin("123456")
        self.enrolled_device.save()
        self.set_permissions("mdm.view_device_lock_pin")
        response = self.get(reverse("mdm_api:enrolled_device_device_lock_pin", args=(self.enrolled_device.pk,)))
        self.assertEqual(
            response.json(),
            {"id": self.enrolled_device.pk,
             "serial_number": self.enrolled_device.serial_number,
             "device_lock_pin": "123456"}
        )
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, DeviceLockPinViewedEvent)
        self.assertEqual(event.metadata.machine_serial_number, self.enrolled_device.serial_number)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enrolled_device_device_lock_pin_login(self, post_event):
        self.enrolled_device.platform = Platform.MACOS
        self.enrolled_device.set_device_lock_pin("123456")
        self.enrolled_device.save()
        self.login("mdm.view_device_lock_pin")
        response = self.get(reverse("mdm_api:enrolled_device_device_lock_pin", args=(self.enrolled_device.pk,)),
                            include_token=False)
        self.assertEqual(
            response.json(),
            {"id": self.enrolled_device.pk,
             "serial_number": self.enrolled_device.serial_number,
             "device_lock_pin": "123456"}
        )
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, DeviceLockPinViewedEvent)
        self.assertEqual(event.metadata.machine_serial_number, self.enrolled_device.serial_number)