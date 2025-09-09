from functools import reduce
import operator
import plistlib
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import APIToken, User
from zentral.contrib.inventory.models import MetaBusinessUnit, MachineTag, Tag
from zentral.contrib.mdm.commands.base import load_command
from zentral.contrib.mdm.events import FileVaultPRKViewedEvent, RecoveryPasswordViewedEvent
from zentral.contrib.mdm.models import Platform
from .utils import force_dep_enrollment_session


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
                          'user_enrollment': None}]}
        )

    def test_enrolled_devices_by_serial_number(self):
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.get(
            reverse("mdm_api:enrolled_devices")
            + f"?serial_number={self.enrolled_device.serial_number}"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'count': 1,
             'next': None,
             'previous': None,
             'results': [{'activation_lock_manageable': None,
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
                          'user_enrollment': None}]}
        )

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
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'count': 1,
             'next': None,
             'previous': None,
             'results': [{'activation_lock_manageable': None,
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
                          'user_enrollment': None}]}
        )

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
                          'user_enrollment': None}]}
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
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'count': 1,
             'next': None,
             'previous': None,
             'results': [{'activation_lock_manageable': None,
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
                          'user_enrollment': None}]}
        )

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

    # block enrolled device

    def test_block_enrolled_device_unauthorized(self):
        response = self.post(reverse("mdm_api:block_enrolled_device", args=(self.enrolled_device.pk,)), None,
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_block_enrolled_device_permission_denied(self):
        self.set_permissions("mdm.view_enrolleddevice")
        response = self.post(reverse("mdm_api:block_enrolled_device", args=(self.enrolled_device.pk,)), None)
        self.assertEqual(response.status_code, 403)

    def test_block_enrolled_device_already_blocked(self):
        self.enrolled_device.block()
        self.set_permissions("mdm.change_enrolleddevice")
        response = self.post(reverse("mdm_api:block_enrolled_device", args=(self.enrolled_device.pk,)), None)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"detail": "Device already blocked."})

    def test_block_enrolled_device(self):
        self.enrolled_device.unblock()
        self.set_permissions("mdm.change_enrolleddevice")
        response = self.post(reverse("mdm_api:block_enrolled_device", args=(self.enrolled_device.pk,)), None)
        self.assertEqual(response.status_code, 200)
        self.enrolled_device.refresh_from_db()
        self.assertEqual(
            response.json(),
            {'activation_lock_manageable': None,
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
             'user_enrollment': None}
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
             'user_enrollment': None}
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
