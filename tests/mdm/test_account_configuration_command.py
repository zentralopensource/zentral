import plistlib
from unittest.mock import Mock
from django.test import TestCase
from django.utils.crypto import get_random_string
from realms.utils import serialize_password_hash_dict
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import AccountConfiguration
from zentral.contrib.mdm.commands.scheduling import _configure_dep_enrollment_accounts
from zentral.contrib.mdm.models import Channel, Command, DEPEnrollment, Platform, RequestStatus
from .utils import force_dep_enrollment_session, force_enrolled_user, force_ota_enrollment_session


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
            realm_user=True,
            realm_user_username="yolo.fomo@example.com",
            realm_user_email="un.deux@example.com",
        )

    # verify_channel_and_device

    def test_scope_ok(self):
        self.assertEqual(self.dep_enrollment_session.enrolled_device.platform, Platform.MACOS)
        self.assertTrue(AccountConfiguration.verify_channel_and_device(
            Channel.DEVICE,
            self.dep_enrollment_session.enrolled_device,
        ))

    def test_user_channel_scope_not_ok(self):
        self.assertEqual(self.dep_enrollment_session.enrolled_device.platform, Platform.MACOS)
        self.assertFalse(AccountConfiguration.verify_channel_and_device(
            Channel.USER,
            self.dep_enrollment_session.enrolled_device,
        ))

    def test_not_macos_scope_not_ok(self):
        self.dep_enrollment_session.enrolled_device.platform = Platform.IOS
        self.assertFalse(AccountConfiguration.verify_channel_and_device(
            Channel.DEVICE,
            self.dep_enrollment_session.enrolled_device,
        ))

    # build_command

    def test_build_command_realm_user_no_password_hash_admin_default_username(self):
        cmd = AccountConfiguration.create_for_device(
            self.dep_enrollment_session.enrolled_device
        )
        self.assertEqual(self.dep_enrollment_session.dep_enrollment.username_pattern,
                         DEPEnrollment.UsernamePattern.DEVICE_USERNAME)
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(payload["AutoSetupAdminAccounts"], [])
        self.assertFalse(payload["DontAutoPopulatePrimaryAccountInfo"])
        self.assertTrue(payload["LockPrimaryAccountInfo"])
        self.assertEqual(payload["PrimaryAccountFullName"], self.dep_enrollment_session.realm_user.get_full_name())
        self.assertEqual(payload["PrimaryAccountUserName"], "yolofomo")
        self.assertFalse(payload["SetPrimarySetupAccountAsRegularUser"])
        self.assertFalse(payload["SkipPrimarySetupAccountCreation"])

    def test_build_command_realm_user_no_password_hash_admin_email_prefix_username(self):
        cmd = AccountConfiguration.create_for_device(
            self.dep_enrollment_session.enrolled_device
        )
        self.dep_enrollment_session.dep_enrollment.username_pattern = DEPEnrollment.UsernamePattern.EMAIL_PREFIX
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(payload["AutoSetupAdminAccounts"], [])
        self.assertFalse(payload["DontAutoPopulatePrimaryAccountInfo"])
        self.assertTrue(payload["LockPrimaryAccountInfo"])
        self.assertEqual(payload["PrimaryAccountFullName"], self.dep_enrollment_session.realm_user.get_full_name())
        self.assertEqual(payload["PrimaryAccountUserName"], "un.deux")
        self.assertFalse(payload["SetPrimarySetupAccountAsRegularUser"])
        self.assertFalse(payload["SkipPrimarySetupAccountCreation"])

    def test_ota_enrollment_session_error(self):
        session, _, _ = force_ota_enrollment_session(self.mbu, completed=True)
        cmd = AccountConfiguration.create_for_device(session.enrolled_device)
        with self.assertRaises(ValueError) as cm:
            cmd.build_http_response(session)
        self.assertEqual(cm.exception.args[0], "Invalid enrollment session")

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

    def test_build_command_no_realm_user_hard_coded_admin_auto_advance_setup(self):
        self.dep_enrollment_session.realm_user = None
        self.dep_enrollment_session.save()
        dep_enrollment = self.dep_enrollment_session.dep_enrollment
        dep_enrollment.use_realm_user = False
        dep_enrollment.auto_advance_setup = True
        dep_enrollment.admin_full_name = "Admin Full Name"
        dep_enrollment.admin_short_name = "admin_short_name"
        dep_enrollment.admin_password_hash = {"SALTED-SHA512-PBKDF2": {"fake": True}}
        dep_enrollment.save()
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
        self.assertTrue(payload["DontAutoPopulatePrimaryAccountInfo"])
        self.assertTrue(payload["SkipPrimarySetupAccountCreation"])
        self.assertNotIn("LockPrimaryAccountInfo", payload)
        self.assertNotIn("PrimaryAccountFullName", payload)
        self.assertNotIn("PrimaryAccountUserName", payload)
        self.assertNotIn("SetPrimarySetupAccountAsRegularUser", payload)

    # _configure_dep_enrollment_accounts

    def test_configure_dep_enrollment_accounts_not_now(self):
        self.dep_enrollment_session.enrolled_device.awaiting_configuration = True
        self.assertIsNone(_configure_dep_enrollment_accounts(
            Target(self.dep_enrollment_session.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.NOT_NOW,
        ))

    def test_configure_dep_enrollment_accounts_user_channel(self):
        self.dep_enrollment_session.enrolled_device.awaiting_configuration = True
        enrolled_user = force_enrolled_user(self.dep_enrollment_session.enrolled_device)
        self.assertIsNone(_configure_dep_enrollment_accounts(
            Target(self.dep_enrollment_session.enrolled_device, enrolled_user),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_configure_dep_enrollment_accounts_not_awaiting_configuration(self):
        self.assertIsNone(self.dep_enrollment_session.enrolled_device.awaiting_configuration)
        self.assertIsNone(_configure_dep_enrollment_accounts(
            Target(self.dep_enrollment_session.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_configure_dep_enrollment_accounts_not_dep_enrollment_session(self):
        self.dep_enrollment_session.enrolled_device.awaiting_configuration = True
        self.assertIsNone(_configure_dep_enrollment_accounts(
            Target(self.dep_enrollment_session.enrolled_device),
            Mock(dep_enrollment=None),
            RequestStatus.IDLE,
        ))

    def test_configure_dep_enrollment_accounts_not_requires_account_configuration(self):
        dep_enrollment_session, _, _ = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        dep_enrollment_session.enrolled_device.awaiting_configuration = True
        self.assertFalse(dep_enrollment_session.dep_enrollment.requires_account_configuration())
        self.assertIsNone(_configure_dep_enrollment_accounts(
            Target(dep_enrollment_session.enrolled_device),
            dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_configure_dep_enrollment_accounts_already_done(self):
        self.dep_enrollment_session.enrolled_device.awaiting_configuration = True
        self.dep_enrollment_session.dep_enrollment.use_realm_user = True
        self.assertTrue(self.dep_enrollment_session.dep_enrollment.requires_account_configuration())
        cmd = AccountConfiguration.create_for_device(self.dep_enrollment_session.enrolled_device)
        cmd.db_command.status = Command.Status.ACKNOWLEDGED
        cmd.db_command.save()
        self.assertIsNone(_configure_dep_enrollment_accounts(
            Target(self.dep_enrollment_session.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_configure_dep_enrollment_accounts(self):
        self.dep_enrollment_session.enrolled_device.awaiting_configuration = True
        self.dep_enrollment_session.dep_enrollment.use_realm_user = True
        self.assertTrue(self.dep_enrollment_session.dep_enrollment.requires_account_configuration())
        cmd = _configure_dep_enrollment_accounts(
            Target(self.dep_enrollment_session.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, AccountConfiguration)
