import copy
from datetime import datetime
import os.path
import plistlib
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import SecurityInfo
from .utils import force_dep_enrollment_session


class SecurityInfoCommandTestCase(TestCase):
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
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device
        cls.security_info = plistlib.load(
            open(os.path.join(os.path.dirname(__file__),
                              "testdata/security_info.plist"),
                 "rb")
        )

    def test_build_command(self):
        cmd = SecurityInfo.create_for_device(
            self.dep_enrollment_session.enrolled_device
        )
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(payload["RequestType"], "SecurityInfo")

    def test_empty_response(self):
        self.assertIsNone(self.enrolled_device.security_info)
        self.assertIsNone(self.enrolled_device.security_info_updated_at)
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        cmd.process_response({"Status": "Acknowledged"}, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertIsNone(self.enrolled_device.security_info)
        self.assertIsNone(self.enrolled_device.security_info_updated_at)

    def test_process_acknowledged_response(self):
        start = datetime.utcnow()
        self.assertIsNone(self.enrolled_device.security_info)
        self.assertIsNone(self.enrolled_device.security_info_updated_at)
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        cmd.process_response(self.security_info, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertTrue(self.enrolled_device.security_info_updated_at > start)
        self.assertTrue(self.enrolled_device.security_info["FDE_Enabled"])
        self.assertTrue(self.enrolled_device.security_info_updated_at > start)
        self.assertFalse(self.enrolled_device.dep_enrollment)
        self.assertTrue(self.enrolled_device.activation_lock_manageable)
        self.assertFalse(self.enrolled_device.user_enrollment)
        self.assertTrue(self.enrolled_device.user_approved_enrollment)
        self.assertFalse(self.enrolled_device.bootstrap_token_allowed_for_authentication)
        self.assertTrue(self.enrolled_device.bootstrap_token_required_for_software_update)
        self.assertTrue(self.enrolled_device.bootstrap_token_required_for_kext_approval)

    def test_process_acknowledged_response_btafa_allowed(self):
        start = datetime.utcnow()
        self.assertIsNone(self.enrolled_device.security_info)
        self.assertIsNone(self.enrolled_device.security_info_updated_at)
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        security_info = copy.deepcopy(self.security_info)
        security_info["SecurityInfo"]["BootstrapTokenAllowedForAuthentication"] = "allowed"
        cmd.process_response(security_info, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertTrue(self.enrolled_device.security_info_updated_at > start)
        self.assertTrue(self.enrolled_device.bootstrap_token_allowed_for_authentication)

    def test_process_acknowledged_response_btafa_not_supported(self):
        start = datetime.utcnow()
        self.assertIsNone(self.enrolled_device.security_info)
        self.assertIsNone(self.enrolled_device.security_info_updated_at)
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        security_info = copy.deepcopy(self.security_info)
        security_info["SecurityInfo"]["BootstrapTokenAllowedForAuthentication"] = "not supported"
        cmd.process_response(security_info, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertTrue(self.enrolled_device.security_info_updated_at > start)
        self.assertIsNone(self.enrolled_device.bootstrap_token_allowed_for_authentication)
