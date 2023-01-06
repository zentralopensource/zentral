import plistlib
from unittest.mock import Mock
from django.test import TestCase
from django.utils.crypto import get_random_string
from realms.utils import serialize_password_hash_dict
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import AccountConfiguration
from zentral.contrib.mdm.commands.scheduling import _configure_dep_enrollment_accounts
from zentral.contrib.mdm.models import Channel, CommandStatus, Platform, RequestStatus
from .utils import force_dep_enrollment_session, force_enrolled_user


class AccountConfigurationCommandTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.dep_enrollment_session, _, _ = force_dep_enrollment_session(
            cls.mbu,
            authenticated=True,
            completed=True,
            realm_user=True
        )

    # verify_channel_and_device

    def test_scope_ok(self):
        self.assertEqual(self.dep_enrollment_session.enrolled_device.platform, Platform.macOS.name)
        self.assertTrue(AccountConfiguration.verify_channel_and_device(
            Channel.Device,
            self.dep_enrollment_session.enrolled_device,
        ))

    def test_user_channel_scope_not_ok(self):
        self.assertEqual(self.dep_enrollment_session.enrolled_device.platform, Platform.macOS.name)
        self.assertFalse(AccountConfiguration.verify_channel_and_device(
            Channel.User,
            self.dep_enrollment_session.enrolled_device,
        ))

    def test_not_macos_scope_not_ok(self):
        self.dep_enrollment_session.enrolled_device.platform = Platform.iOS.name
        self.assertFalse(AccountConfiguration.verify_channel_and_device(
            Channel.Device,
            self.dep_enrollment_session.enrolled_device,
        ))

    # build_command

    def test_build_command_realm_user_no_password_hash_admin(self):
        cmd = AccountConfiguration.create_for_device(
            self.dep_enrollment_session.enrolled_device
        )
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(payload["AutoSetupAdminAccounts"], [])
        self.assertFalse(payload["DontAutoPopulatePrimaryAccountInfo"])
        self.assertTrue(payload["LockPrimaryAccountInfo"])
        self.assertEqual(payload["PrimaryAccountFullName"], self.dep_enrollment_session.realm_user.get_full_name())
        self.assertEqual(payload["PrimaryAccountUserName"], self.dep_enrollment_session.realm_user.device_username)
        self.assertFalse(payload["SetPrimarySetupAccountAsRegularUser"])
        self.assertFalse(payload["SkipPrimarySetupAccountCreation"])

    def test_build_command_realm_user_no_password_hash_not_admin(self):
        dep_enrollment = self.dep_enrollment_session.dep_enrollment
        dep_enrollment.realm_user_is_admin = False
        dep_enrollment.admin_full_name = "Admin Full Name"
        dep_enrollment.admin_short_name = "admin_short_name"
        dep_enrollment.admin_password_hash = {"SALTED-SHA512-PBKDF2": {"fake": True}}
        cmd = AccountConfiguration.create_for_device(
            self.dep_enrollment_session.enrolled_device
        )
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(
            payload["AutoSetupAdminAccounts"],
            [{"fullName": "Admin Full Name",
              "shortName": "admin_short_name",
              "hidden": True,
              "passwordHash": serialize_password_hash_dict(dep_enrollment.admin_password_hash)}]
        )
        self.assertFalse(payload["DontAutoPopulatePrimaryAccountInfo"])
        self.assertTrue(payload["LockPrimaryAccountInfo"])
        self.assertEqual(payload["PrimaryAccountFullName"], self.dep_enrollment_session.realm_user.get_full_name())
        self.assertEqual(payload["PrimaryAccountUserName"], self.dep_enrollment_session.realm_user.device_username)
        self.assertTrue(payload["SetPrimarySetupAccountAsRegularUser"])
        self.assertFalse(payload["SkipPrimarySetupAccountCreation"])

    def test_build_command_realm_user_password_hash_admin(self):
        password_hash = {"SALTED-SHA512-PBKDF2": {"fake": True}}
        self.dep_enrollment_session.realm_user.password_hash = password_hash
        cmd = AccountConfiguration.create_for_device(
            self.dep_enrollment_session.enrolled_device
        )
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertTrue(payload["DontAutoPopulatePrimaryAccountInfo"])
        self.assertTrue(payload["SkipPrimarySetupAccountCreation"])
        self.assertEqual(
            payload["AutoSetupAdminAccounts"],
            [{"fullName": self.dep_enrollment_session.realm_user.get_full_name(),
              "shortName": self.dep_enrollment_session.realm_user.device_username,
              "hidden": False,
              "passwordHash": serialize_password_hash_dict(password_hash)}]
        )

    # _configure_dep_enrollment_accounts

    def test_configure_dep_enrollment_accounts_not_now(self):
        self.dep_enrollment_session.enrolled_device.awaiting_configuration = True
        self.assertIsNone(_configure_dep_enrollment_accounts(
            Channel.Device, RequestStatus.NotNow,
            self.dep_enrollment_session,
            self.dep_enrollment_session.enrolled_device,
            None
        ))

    def test_configure_dep_enrollment_accounts_user_channel(self):
        self.dep_enrollment_session.enrolled_device.awaiting_configuration = True
        enrolled_user = force_enrolled_user(self.dep_enrollment_session.enrolled_device)
        self.assertIsNone(_configure_dep_enrollment_accounts(
            Channel.User, RequestStatus.Idle,
            self.dep_enrollment_session,
            self.dep_enrollment_session.enrolled_device,
            enrolled_user
        ))

    def test_configure_dep_enrollment_accounts_not_awaiting_configuration(self):
        self.assertIsNone(self.dep_enrollment_session.enrolled_device.awaiting_configuration)
        self.assertIsNone(_configure_dep_enrollment_accounts(
            Channel.Device, RequestStatus.Idle,
            self.dep_enrollment_session,
            self.dep_enrollment_session.enrolled_device,
            None
        ))

    def test_configure_dep_enrollment_accounts_not_dep_enrollment_session(self):
        self.dep_enrollment_session.enrolled_device.awaiting_configuration = True
        self.assertIsNone(_configure_dep_enrollment_accounts(
            Channel.Device, RequestStatus.Idle,
            Mock(dep_enrollment=None),
            self.dep_enrollment_session.enrolled_device,
            None
        ))

    def test_configure_dep_enrollment_accounts_not_requires_account_configuration(self):
        dep_enrollment_session, _, _ = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        dep_enrollment_session.enrolled_device.awaiting_configuration = True
        self.assertFalse(dep_enrollment_session.dep_enrollment.requires_account_configuration())
        self.assertIsNone(_configure_dep_enrollment_accounts(
            Channel.Device, RequestStatus.Idle,
            dep_enrollment_session,
            dep_enrollment_session.enrolled_device,
            None
        ))

    def test_configure_dep_enrollment_accounts_already_done(self):
        self.dep_enrollment_session.enrolled_device.awaiting_configuration = True
        self.dep_enrollment_session.dep_enrollment.use_realm_user = True
        self.assertTrue(self.dep_enrollment_session.dep_enrollment.requires_account_configuration())
        cmd = AccountConfiguration.create_for_device(self.dep_enrollment_session.enrolled_device)
        cmd.db_command.status = CommandStatus.Acknowledged.value
        cmd.db_command.save()
        self.assertIsNone(_configure_dep_enrollment_accounts(
            Channel.Device, RequestStatus.Idle,
            self.dep_enrollment_session,
            self.dep_enrollment_session.enrolled_device,
            None
        ))

    def test_configure_dep_enrollment_accounts(self):
        self.dep_enrollment_session.enrolled_device.awaiting_configuration = True
        self.dep_enrollment_session.dep_enrollment.use_realm_user = True
        self.assertTrue(self.dep_enrollment_session.dep_enrollment.requires_account_configuration())
        cmd = _configure_dep_enrollment_accounts(
            Channel.Device, RequestStatus.Idle,
            self.dep_enrollment_session,
            self.dep_enrollment_session.enrolled_device,
            None
        )
        self.assertIsInstance(cmd, AccountConfiguration)
