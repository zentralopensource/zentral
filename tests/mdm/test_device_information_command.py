import copy
from datetime import datetime
import os.path
import plistlib
from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.inventory.models import MetaBusinessUnit, MetaMachine
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import DeviceInformation, SecurityInfo
from zentral.contrib.mdm.commands.scheduling import _update_base_inventory
from zentral.contrib.mdm.models import Blueprint, Channel, Platform, RequestStatus
from .utils import force_dep_enrollment_session


class DeviceInformationCommandTestCase(TestCase):
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
        cls.device_information = plistlib.load(
            open(os.path.join(os.path.dirname(__file__),
                              "testdata/device_information.plist"),
                 "rb")
        )
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device
        blueprint = Blueprint.objects.create(name=get_random_string(12))
        cls.enrolled_device.blueprint = blueprint
        cls.enrolled_device.save()

    # verify_channel_and_device

    def test_scope(self):
        for channel, platform, user_enrollment, result in (
            (Channel.DEVICE, Platform.IOS, False, True),
            (Channel.DEVICE, Platform.IPADOS, False, True),
            (Channel.DEVICE, Platform.MACOS, False, True),
            (Channel.DEVICE, Platform.TVOS, False, True),
            (Channel.USER, Platform.IOS, False, False),
            (Channel.USER, Platform.IPADOS, False, True),
            (Channel.USER, Platform.MACOS, False, True),
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
                DeviceInformation.verify_channel_and_device(
                    channel, self.enrolled_device
                )
            )

    # build_command

    def test_queries(self):
        for key, access_right, platforms in DeviceInformation.queries:
            self.assertIsInstance(key, str)
            self.assertIn(access_right, (None, 16, 32, 4096))
            if platforms is not None:
                self.assertIsInstance(platforms, dict)
                for platform, min_os_version in platforms.items():
                    self.assertIn(platform, Platform.values)
                    self.assertIsInstance(min_os_version, tuple)
                    self.assertTrue(all(isinstance(i, int) for i in min_os_version))

    def test_build_command(self):
        cmd = DeviceInformation.create_for_device(
            self.dep_enrollment_session.enrolled_device
        )
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(payload["RequestType"], "DeviceInformation")
        self.assertIn("Queries", payload)
        for key in payload["Queries"]:
            self.assertIsInstance(key, str)

    # process_response

    def test_process_missing_query_responses(self):
        response = copy.deepcopy(self.device_information)
        response.pop("QueryResponses")
        enrolled_device = self.dep_enrollment_session.enrolled_device
        enrolled_device.os_version = "13.4.1"
        enrolled_device.save()
        cmd = DeviceInformation.create_for_device(
            self.dep_enrollment_session.enrolled_device
        )
        cmd.process_response(response, self.dep_enrollment_session, self.mbu)
        enrolled_device.refresh_from_db()
        self.assertEqual(enrolled_device.os_version, "13.4.1")

    def test_process_platform_change(self):
        response = copy.deepcopy(self.device_information)
        response["QueryResponses"]["ProductName"] = "iPhone14"
        enrolled_device = self.dep_enrollment_session.enrolled_device
        self.assertEqual(enrolled_device.platform, "macOS")
        cmd = DeviceInformation.create_for_device(
            self.dep_enrollment_session.enrolled_device
        )
        cmd.process_response(response, self.dep_enrollment_session, self.mbu)
        enrolled_device.refresh_from_db()
        self.assertEqual(enrolled_device.platform, "iOS")

    def test_process_acknowledged_response(self):
        start = datetime.utcnow()
        enrolled_device = self.dep_enrollment_session.enrolled_device
        enrolled_device.os_version_extra = "(a)"
        enrolled_device.build_version_extra = "YOLOa"
        self.assertIsNone(enrolled_device.device_information_updated_at)
        m0 = MetaMachine(self.dep_enrollment_session.enrolled_device.serial_number)
        self.assertEqual(len(m0.snapshots), 0)
        cmd = DeviceInformation.create_for_device(
            self.dep_enrollment_session.enrolled_device
        )
        cmd.process_response(self.device_information, self.dep_enrollment_session, self.mbu)
        cmd.db_command.refresh_from_db()
        self.assertIsNotNone(cmd.db_command.result)
        self.assertIn("QueryResponses", cmd.response)
        m = MetaMachine(enrolled_device.serial_number)
        self.assertEqual(len(m.snapshots), 1)
        ms = m.snapshots[0]
        self.assertEqual(ms.source.module, "zentral.contrib.mdm")
        enrolled_device.refresh_from_db()
        self.assertEqual(enrolled_device.device_information["ActiveManagedUsers"],
                         ["5DF1182E-C70B-4A3A-BADC-DD3E775040FB"])
        self.assertTrue(enrolled_device.device_information_updated_at > start)
        self.assertEqual(enrolled_device.platform, "macOS")
        self.assertEqual(enrolled_device.os_version, "13.0")
        self.assertEqual(enrolled_device.os_version_extra, "")
        self.assertEqual(enrolled_device.build_version, "22A5321d")
        self.assertEqual(enrolled_device.build_version_extra, "")
        self.assertEqual(enrolled_device.full_os_version, "13.0 (22A5321d)")
        self.assertTrue(enrolled_device.apple_silicon)
        self.assertTrue(enrolled_device.supervised)
        self.assertEqual(enrolled_device.name, "Yolo")
        self.assertEqual(enrolled_device.model, "VirtualMac2,1")

    def test_process_acknowledged_response_missing_info(self):
        start = datetime.utcnow()
        enrolled_device = self.dep_enrollment_session.enrolled_device
        self.assertIsNone(enrolled_device.device_information_updated_at)
        m0 = MetaMachine(self.dep_enrollment_session.enrolled_device.serial_number)
        self.assertEqual(len(m0.snapshots), 0)
        cmd = DeviceInformation.create_for_device(
            self.dep_enrollment_session.enrolled_device
        )
        device_information = copy.deepcopy(self.device_information)
        for key in ("DeviceName", "ProductName", "Model", "SerialNumber", "OSVersion", "BuildVersion"):
            device_information["QueryResponses"].pop(key)
        cmd.process_response(device_information, self.dep_enrollment_session, self.mbu)
        cmd.db_command.refresh_from_db()
        self.assertIsNotNone(cmd.db_command.result)
        self.assertIn("QueryResponses", cmd.response)
        m = MetaMachine(enrolled_device.serial_number)
        self.assertEqual(len(m.snapshots), 1)
        ms = m.snapshots[0]
        self.assertEqual(ms.source.module, "zentral.contrib.mdm")
        enrolled_device.refresh_from_db()
        self.assertEqual(enrolled_device.device_information["ActiveManagedUsers"],
                         ["5DF1182E-C70B-4A3A-BADC-DD3E775040FB"])
        self.assertTrue(enrolled_device.device_information_updated_at > start)
        self.assertEqual(enrolled_device.platform, "macOS")
        self.assertEqual(enrolled_device.os_version, "")
        self.assertEqual(enrolled_device.os_version_extra, "")
        self.assertEqual(enrolled_device.build_version, "")
        self.assertEqual(enrolled_device.build_version_extra, "")
        self.assertEqual(enrolled_device.full_os_version, "")
        self.assertTrue(enrolled_device.apple_silicon)
        self.assertTrue(enrolled_device.supervised)
        self.assertIsNone(enrolled_device.name)
        self.assertIsNone(enrolled_device.model)

    def test_process_acknowledged_response_supplemental_build_version_same_as_build_version(self):
        response = copy.deepcopy(self.device_information)
        response["QueryResponses"]["SupplementalBuildVersion"] = response["QueryResponses"]["BuildVersion"]
        cmd = DeviceInformation.create_for_device(
            self.dep_enrollment_session.enrolled_device
        )
        cmd.process_response(response, self.dep_enrollment_session, self.mbu)
        enrolled_device = self.dep_enrollment_session.enrolled_device
        self.assertEqual(enrolled_device.os_version, "13.0")
        self.assertEqual(enrolled_device.os_version_extra, "")
        self.assertEqual(enrolled_device.build_version, "22A5321d")
        self.assertEqual(enrolled_device.build_version_extra, "")
        self.assertEqual(enrolled_device.full_os_version, "13.0 (22A5321d)")

    def test_process_acknowledged_response_rsr(self):
        response = copy.deepcopy(self.device_information)
        response["QueryResponses"]["SupplementalBuildVersion"] = "22E772610a"
        response["QueryResponses"]["SupplementalOSVersionExtra"] = "(a)"
        cmd = DeviceInformation.create_for_device(
            self.dep_enrollment_session.enrolled_device
        )
        cmd.process_response(response, self.dep_enrollment_session, self.mbu)
        enrolled_device = self.dep_enrollment_session.enrolled_device
        self.assertEqual(enrolled_device.os_version, "13.0")
        self.assertEqual(enrolled_device.os_version_extra, "(a)")
        self.assertEqual(enrolled_device.build_version, "22A5321d")
        self.assertEqual(enrolled_device.build_version_extra, "22E772610a")
        self.assertEqual(enrolled_device.full_os_version, "13.0 (a) (22E772610a)")

    # _update_base_inventory

    def test_update_base_inventory_device_information_updated_at_none(self):
        self.assertIsNone(self.enrolled_device.device_information_updated_at)
        cmd = _update_base_inventory(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, DeviceInformation)

    def test_update_base_inventory_device_information_updated_at_old(self):
        self.enrolled_device.device_information_updated_at = datetime(2000, 1, 1)
        cmd = _update_base_inventory(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, DeviceInformation)

    def test_update_base_inventory_device_information_updated_at_ok(self):
        self.enrolled_device.device_information_updated_at = datetime.utcnow()
        self.assertIsNone(self.enrolled_device.security_info_updated_at)
        cmd = _update_base_inventory(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, SecurityInfo)
