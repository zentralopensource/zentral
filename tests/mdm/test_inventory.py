from datetime import datetime
import os.path
import plistlib
from django.test import TestCase
from django.utils.crypto import get_random_string
from realms.models import RealmGroup, RealmTagMapping, RealmUserGroupMembership
from zentral.contrib.inventory.models import MachineTag, MetaBusinessUnit, MetaMachine, Tag
from zentral.contrib.mdm.commands.certificate_list import CertificateList
from zentral.contrib.mdm.commands.device_information import DeviceInformation
from zentral.contrib.mdm.commands.installed_application_list import InstalledApplicationList
from zentral.contrib.mdm.commands.profile_list import ProfileList
from zentral.contrib.mdm.inventory import ms_tree_from_payload, update_realm_tags
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
        cls.realm_user = cls.dep_enrollment_session.realm_user
        cls.realm = cls.realm_user.realm
        cls.blueprint = Blueprint.objects.create(
            name=get_random_string(32),
            collect_apps=Blueprint.InventoryItemCollectionOption.ALL,
            collect_certificates=Blueprint.InventoryItemCollectionOption.ALL,
            collect_profiles=Blueprint.InventoryItemCollectionOption.ALL,
        )
        cls.enrolled_device.blueprint = cls.blueprint
        cls.enrolled_device.save()

    def read_plist(self, filename):
        return plistlib.load(
            open(os.path.join(os.path.dirname(__file__),
                              "testdata", filename),
                 "rb")
        )

    def test_ms_tree_from_payload(self):
        device_information = self.read_plist("device_information.plist")
        ms_tree = ms_tree_from_payload(device_information["QueryResponses"])
        self.assertEqual(ms_tree["system_info"]["computer_name"], "Yolo")
        self.assertEqual(ms_tree["system_info"]["hardware_model"], "VirtualMac2,1")
        self.assertEqual(ms_tree["os_version"]["name"], "macOS")
        self.assertEqual(ms_tree["os_version"]["major"], 13)
        self.assertEqual(ms_tree["os_version"]["minor"], 0)
        self.assertEqual(ms_tree["os_version"]["patch"], 0)
        self.assertEqual(ms_tree["os_version"]["build"], "22A5321d")
        self.assertNotIn("version", ms_tree["os_version"])

    def test_ms_tree_from_payload_extra_version(self):
        device_information = self.read_plist("device_information.plist")
        device_information["QueryResponses"]["SupplementalOSVersionExtra"] = "(a)"
        device_information["QueryResponses"]["SupplementalBuildVersion"] = "22E772610a"
        ms_tree = ms_tree_from_payload(device_information["QueryResponses"])
        self.assertEqual(ms_tree["os_version"]["version"], "(a)")
        self.assertEqual(ms_tree["os_version"]["build"], "22E772610a")

    def test_full_inventory_tree(self):
        step1 = datetime.utcnow()
        # certificates
        cmd = CertificateList.create_for_device(
            self.dep_enrollment_session.enrolled_device,
            kwargs={"update_inventory": True},
        )
        cmd.process_response(
            self.read_plist("certificate_list.plist"),
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
            self.read_plist("profile_list.plist"),
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
            self.read_plist("installed_application_list.plist"),
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
            self.read_plist("device_information.plist"),
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
        realm_user = self.dep_enrollment_session.realm_user
        self.assertEqual(
            ms.principal_user.serialize(),
            {"source": {"type": "INVENTORY"},
             "unique_id": str(realm_user.pk),
             "principal_name": realm_user.username,
             "display_name": realm_user.get_full_name()}
        )

    # realm tags

    def test_update_realm_tags(self):
        serial_number = self.enrolled_device.serial_number
        mt_qs = MachineTag.objects.filter(serial_number=serial_number)
        self.assertFalse(mt_qs.exists())

        # tags
        # add realm user to a group
        group = RealmGroup.objects.create(realm=self.realm,
                                          display_name=get_random_string(12))
        sub_group = RealmGroup.objects.create(realm=self.realm,
                                              display_name=get_random_string(12),
                                              parent=group)
        RealmUserGroupMembership.objects.create(user=self.realm_user, group=sub_group)
        # tag to add because of a matching tag mapping
        tag_to_add = Tag.objects.create(name=get_random_string(12))
        RealmTagMapping.objects.create(
            realm=self.realm,
            group_name=group.display_name,  # match on the group
            tag=tag_to_add
        )
        # tag already present
        tag_already_present = Tag.objects.create(name=get_random_string(12))
        RealmTagMapping.objects.create(
            realm=self.realm,
            group_name=sub_group.display_name,  # match on the sub group
            tag=tag_already_present
        )
        MachineTag.objects.create(serial_number=serial_number, tag=tag_already_present)
        # tag not managed via the mappings
        unmanaged_tag = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number=serial_number, tag=unmanaged_tag)
        # tag to remove
        tag_to_remove = Tag.objects.create(name=get_random_string(12))
        RealmTagMapping.objects.create(
            realm=self.realm,
            group_name=get_random_string(12),  # no match
            tag=tag_to_remove
        )
        MachineTag.objects.create(serial_number=serial_number, tag=tag_to_remove)

        self.assertEqual(
            sorted(update_realm_tags(self.realm), key=lambda d: d["tag_id"]),
            sorted(
                [{'serial_number': serial_number, 'tag_id': tag_to_add.pk, 'op': 'c'},
                 {'serial_number': serial_number, 'tag_id': tag_to_remove.pk, 'op': 'd'}],
                key=lambda d: d["tag_id"]
            )
        )
        self.assertEqual(mt_qs.count(), 3)
        self.assertTrue(mt_qs.filter(tag=tag_to_add).exists())
        self.assertTrue(mt_qs.filter(tag=tag_already_present).exists())
        self.assertTrue(mt_qs.filter(tag=unmanaged_tag).exists())
        self.assertFalse(mt_qs.filter(tag=tag_to_remove).exists())
