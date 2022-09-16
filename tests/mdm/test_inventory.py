import os.path
import plistlib
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.mdm.inventory import commit_update_tree, tree_from_payload
from zentral.contrib.inventory.models import MetaBusinessUnit, MetaMachine
from .utils import force_dep_enrollment_session


class MDMInventoryTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.device_information = plistlib.load(
            open(os.path.join(os.path.dirname(__file__),
                              "testdata/device_information.plist"),
                 "rb")
        )

    def test_payload(self):
        session, device_udid, serial_number = force_dep_enrollment_session(self.mbu, completed=True)
        payload = self.device_information["QueryResponses"]
        tree = commit_update_tree(
            session.enrolled_device,
            tree_from_payload(device_udid, serial_number, self.mbu, payload),
            missing_ok=True
        )
        self.assertEqual(tree["serial_number"], serial_number)
        mm = MetaMachine(serial_number)
        self.assertEqual(len(mm.snapshots), 1)
        ms = mm.snapshots[0]
        self.assertEqual(ms.source.name, "MDM")
        system_info = ms.system_info
        self.assertEqual(system_info.computer_name, "Yolo")
        self.assertEqual(system_info.hardware_model, "VirtualMac2,1")
        os_version = ms.os_version
        self.assertEqual(os_version.name, "macOS")
        self.assertEqual(os_version.major, 13)
        self.assertEqual(os_version.minor, 0)
        self.assertEqual(os_version.patch, 0)

    def test_payload_missing_not_ok(self):
        session, device_udid, serial_number = force_dep_enrollment_session(self.mbu, completed=True)
        payload = self.device_information["QueryResponses"]
        tree = commit_update_tree(
            session.enrolled_device,
            tree_from_payload(device_udid, serial_number, self.mbu, payload),
            missing_ok=False
        )
        self.assertIsNone(tree)
        mm = MetaMachine(serial_number)
        self.assertEqual(len(mm.snapshots), 0)
