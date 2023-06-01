import copy
from datetime import datetime
import os.path
import plistlib
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import SecurityInfo
from zentral.contrib.mdm.commands.scheduling import _update_inventory
from zentral.contrib.mdm.models import Blueprint, Channel, Platform, RequestStatus
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
        cls.security_info_ios = plistlib.load(
            open(os.path.join(os.path.dirname(__file__),
                              "testdata/security_info_ios.plist"),
                 "rb")
        )

        cls.blueprint = Blueprint.objects.create(name=get_random_string(12))
        cls.enrolled_device.blueprint = cls.blueprint
        cls.enrolled_device.save()

    # verify_channel_and_device

    def test_scope(self):
        for channel, platform, user_enrollment, result in (
            (Channel.DEVICE, Platform.IOS, False, True),
            (Channel.DEVICE, Platform.IPADOS, False, True),
            (Channel.DEVICE, Platform.MACOS, False, True),
            (Channel.DEVICE, Platform.TVOS, False, True),
            (Channel.USER, Platform.IOS, False, False),
            (Channel.USER, Platform.IPADOS, False, False),
            (Channel.USER, Platform.MACOS, False, False),
            (Channel.USER, Platform.TVOS, False, False),
            (Channel.DEVICE, Platform.IOS, True, True),
            (Channel.DEVICE, Platform.IPADOS, True, False),
            (Channel.DEVICE, Platform.MACOS, True, True),
            (Channel.DEVICE, Platform.TVOS, True, False),
        ):
            self.enrolled_device.platform = platform
            self.enrolled_device.user_enrollment = user_enrollment
            self.assertEqual(
                result,
                SecurityInfo.verify_channel_and_device(
                    channel, self.enrolled_device
                )
            )

    # build_command

    def test_build_command(self):
        cmd = SecurityInfo.create_for_device(
            self.dep_enrollment_session.enrolled_device
        )
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(payload["RequestType"], "SecurityInfo")

    # process_response

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

    def test_process_acknowledged_ios_response(self):
        start = datetime.utcnow()
        self.assertIsNone(self.enrolled_device.security_info)
        self.assertIsNone(self.enrolled_device.security_info_updated_at)
        self.enrolled_device.dep_enrollment = True
        self.enrolled_device.user_enrollment = False
        self.enrolled_device.user_approved_enrollment = True
        self.enrolled_device.save()
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        cmd.process_response(self.security_info_ios, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertTrue(self.enrolled_device.security_info_updated_at > start)
        self.assertTrue(self.enrolled_device.dep_enrollment)
        self.assertIsNone(self.enrolled_device.activation_lock_manageable)
        self.assertFalse(self.enrolled_device.user_enrollment)
        self.assertTrue(self.enrolled_device.user_approved_enrollment)
        self.assertIsNone(self.enrolled_device.bootstrap_token_allowed_for_authentication)
        self.assertIsNone(self.enrolled_device.bootstrap_token_required_for_software_update)
        self.assertIsNone(self.enrolled_device.bootstrap_token_required_for_kext_approval)

    # _update_inventory

    def test_update_inventory_security_info_updated_at_old(self):
        self.enrolled_device.device_information_updated_at = datetime.utcnow()
        self.enrolled_device.security_info_updated_at = datetime(2000, 1, 1)
        cmd = _update_inventory(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, SecurityInfo)

    def test_update_inventory_security_info_updated_at_ok_no_inventory_items_collection_noop(self):
        self.enrolled_device.device_information_updated_at = datetime.utcnow()
        self.enrolled_device.security_info_updated_at = datetime.utcnow()
        self.assertEqual(self.blueprint.collect_apps, Blueprint.InventoryItemCollectionOption.NO)
        self.assertEqual(self.blueprint.collect_certificates, Blueprint.InventoryItemCollectionOption.NO)
        self.assertEqual(self.blueprint.collect_profiles, Blueprint.InventoryItemCollectionOption.NO)
        self.assertIsNone(
            _update_inventory(
                Target(self.enrolled_device),
                self.dep_enrollment_session,
                RequestStatus.IDLE,
            )
        )
