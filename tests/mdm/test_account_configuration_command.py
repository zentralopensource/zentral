import plistlib
from django.test import TestCase
from django.utils.crypto import get_random_string
from realms.utils import serialize_password_hash_dict
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import AccountConfiguration
from .utils import force_dep_enrollment_session


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
