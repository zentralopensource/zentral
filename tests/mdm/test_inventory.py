from datetime import datetime
import os.path
import plistlib
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit, MetaMachine
from zentral.contrib.mdm.commands.certificate_list import CertificateList
from zentral.contrib.mdm.commands.device_information import DeviceInformation
from zentral.contrib.mdm.commands.installed_application_list import InstalledApplicationList
from zentral.contrib.mdm.commands.profile_list import ProfileList
from zentral.contrib.mdm.inventory import ms_tree_from_payload
from zentral.contrib.mdm.models import Blueprint
from .utils import force_dep_enrollment_session


class MDMInventoryTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.dep_enrollment_session, _, _ = force_dep_enrollment_session(
            cls.mbu, authenticated=True, completed=True, realm_user=True
        )
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device
        cls.blueprint = Blueprint.objects.create(
            name=get_random_string(32),
            collect_apps=Blueprint.InventoryItemCollectionOption.ALL,
            collect_certificates=Blueprint.InventoryItemCollectionOption.ALL,
            collect_profiles=Blueprint.InventoryItemCollectionOption.ALL,
        )
        cls.enrolled_device.blueprint = cls.blueprint
        cls.enrolled_device.save()

    def test_ms_tree_from_payload(self):
        device_information = plistlib.load(
            open(os.path.join(os.path.dirname(__file__),
                              "testdata/device_information.plist"),
                 "rb")
        )
        ms_tree = ms_tree_from_payload(device_information["QueryResponses"])
        self.assertEqual(ms_tree["system_info"]["computer_name"], "Yolo")
        self.assertEqual(ms_tree["system_info"]["hardware_model"], "VirtualMac2,1")
        self.assertEqual(ms_tree["os_version"]["name"], "macOS")
        self.assertEqual(ms_tree["os_version"]["major"], 13)
        self.assertEqual(ms_tree["os_version"]["minor"], 0)
        self.assertEqual(ms_tree["os_version"]["patch"], 0)

    def test_full_inventory_tree(self):
        step1 = datetime.utcnow()
        # certificates
        cmd = CertificateList.create_for_device(
            self.dep_enrollment_session.enrolled_device,
            kwargs={"update_inventory": True},
        )
        cmd.process_response(
            plistlib.load(
                open(
                    os.path.join(
                        os.path.dirname(__file__), "testdata/certificate_list.plist"
                    ),
                    "rb",
                )
            ),
            self.dep_enrollment_session, self.mbu
        )
        self.enrolled_device.refresh_from_db()
        self.assertIsNone(self.enrolled_device.apps_updated_at)
        self.assertIsNone(self.enrolled_device.device_information_updated_at)
        self.assertTrue(self.enrolled_device.certificates_updated_at > step1)
        self.assertIsNone(self.enrolled_device.profiles_updated_at)
        # profiles
        step2 = datetime.utcnow()
        cmd = ProfileList.create_for_device(
            self.dep_enrollment_session.enrolled_device,
            kwargs={"update_inventory": True},
        )
        cmd.process_response(
            plistlib.load(
                open(
                    os.path.join(
                        os.path.dirname(__file__), "testdata/profile_list.plist"
                    ),
                    "rb",
                )
            ),
            self.dep_enrollment_session, self.mbu
        )
        self.enrolled_device.refresh_from_db()
        self.assertIsNone(self.enrolled_device.apps_updated_at)
        self.assertIsNone(self.enrolled_device.device_information_updated_at)
        self.assertTrue(self.enrolled_device.certificates_updated_at < step2)
        self.assertTrue(self.enrolled_device.profiles_updated_at > step2)
        # apps
        step3 = datetime.utcnow()
        cmd = InstalledApplicationList.create_for_device(
            self.dep_enrollment_session.enrolled_device,
            kwargs={"update_inventory": True},
        )
        cmd.process_response(
            plistlib.load(
                open(
                    os.path.join(
                        os.path.dirname(__file__), "testdata/installed_application_list.plist"
                    ),
                    "rb",
                )
            ),
            self.dep_enrollment_session, self.mbu
        )
        self.enrolled_device.refresh_from_db()
        self.assertTrue(self.enrolled_device.apps_updated_at > step3)
        self.assertIsNone(self.enrolled_device.device_information_updated_at)
        self.assertTrue(self.enrolled_device.certificates_updated_at < step2)
        self.assertTrue(self.enrolled_device.profiles_updated_at < step3)
        # device information
        step4 = datetime.utcnow()
        cmd = DeviceInformation.create_for_device(self.enrolled_device)
        cmd.process_response(
            plistlib.load(
                open(
                    os.path.join(
                        os.path.dirname(__file__), "testdata/device_information.plist"
                    ),
                    "rb",
                )
            ),
            self.dep_enrollment_session, self.mbu
        )
        self.enrolled_device.refresh_from_db()
        self.assertTrue(self.enrolled_device.apps_updated_at < step4)
        self.assertTrue(self.enrolled_device.device_information_updated_at > step4)
        self.assertTrue(self.enrolled_device.certificates_updated_at < step2)
        self.assertTrue(self.enrolled_device.profiles_updated_at < step3)
        m = MetaMachine(self.enrolled_device.serial_number)
        self.assertEqual(len(m.snapshots), 1)
        ms = m.snapshots[0]
        self.assertEqual(ms.certificates.count(), 1)
        self.assertEqual(ms.profiles.count(), 2)
        self.assertEqual(ms.os_version.build, "22A5321d")
        self.assertEqual(ms.osx_app_instances.count(), 3)
