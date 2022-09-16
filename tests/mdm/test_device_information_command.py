from datetime import datetime
import os.path
import plistlib
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit, MetaMachine
from zentral.contrib.mdm.commands import DeviceInformation
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

    def test_build_command(self):
        cmd = DeviceInformation.create_for_device(
            self.dep_enrollment_session.enrolled_device
        )
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(payload["RequestType"], "DeviceInformation")
        self.assertIn("Queries", payload)

    def test_process_acknowledged_response(self):
        start = datetime.utcnow()
        enrolled_device = self.dep_enrollment_session.enrolled_device
        self.assertIsNone(enrolled_device.device_information_updated_at)
        m0 = MetaMachine(self.dep_enrollment_session.enrolled_device.serial_number)
        self.assertEqual(len(m0.snapshots), 0)
        cmd = DeviceInformation.create_for_device(
            self.dep_enrollment_session.enrolled_device
        )
        cmd.process_response(self.device_information, self.dep_enrollment_session, self.mbu)
        cmd.db_command.refresh_from_db()
        self.assertIsNone(cmd.db_command.result)
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
        self.assertTrue(enrolled_device.apple_silicon)
        self.assertTrue(enrolled_device.supervised)
