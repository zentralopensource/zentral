from datetime import datetime
import os.path
import plistlib
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit, MetaMachine
from zentral.contrib.mdm.commands import InstalledApplicationList
from zentral.contrib.mdm.commands.scheduling import _update_inventory
from zentral.contrib.mdm.models import Blueprint, Channel, Platform, RequestStatus
from .utils import force_dep_enrollment_session


class InstalledApplicationListCommandTestCase(TestCase):
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
        cls.blueprint = Blueprint.objects.create(
            name=get_random_string(32),
            collect_apps=Blueprint.InventoryItemCollectionOption.ALL,
        )
        cls.enrolled_device.blueprint = cls.blueprint
        cls.enrolled_device.save()
        cls.installed_application_list = plistlib.load(
            open(os.path.join(os.path.dirname(__file__),
                              "testdata/installed_application_list.plist"),
                 "rb")
        )

    # verify_channel_and_device

    def test_scope(self):
        for channel, platform, user_enrollment, result in (
            (Channel.Device, Platform.iOS, False, True),
            (Channel.Device, Platform.iPadOS, False, True),
            (Channel.Device, Platform.macOS, False, True),
            (Channel.Device, Platform.tvOS, False, True),
            (Channel.User, Platform.iOS, False, False),
            (Channel.User, Platform.iPadOS, False, False),
            (Channel.User, Platform.macOS, False, True),
            (Channel.User, Platform.tvOS, False, False),
            (Channel.Device, Platform.iOS, True, True),
            (Channel.Device, Platform.iPadOS, True, False),
            (Channel.Device, Platform.macOS, True, False),
            (Channel.Device, Platform.tvOS, True, False),
            (Channel.User, Platform.iOS, True, False),
            (Channel.User, Platform.iPadOS, True, False),
            (Channel.User, Platform.macOS, True, False),
            (Channel.User, Platform.tvOS, True, False),
        ):
            self.enrolled_device.platform = platform.name
            self.enrolled_device.user_enrollment = user_enrollment
            self.assertEqual(
                result,
                InstalledApplicationList.verify_channel_and_device(channel, self.enrolled_device),
            )

    # load_kwargs

    def test_load_kwargs_defaults(self):
        cmd = InstalledApplicationList.create_for_device(
            self.enrolled_device,
        )
        self.assertFalse(cmd.managed_only)
        self.assertFalse(cmd.update_inventory)
        self.assertTrue(cmd.store_result)

    def test_load_kwargs(self):
        cmd = InstalledApplicationList.create_for_device(
            self.enrolled_device,
            kwargs={"managed_only": True,
                    "update_inventory": True}
        )
        self.assertTrue(cmd.managed_only)
        self.assertTrue(cmd.update_inventory)
        self.assertTrue(cmd.store_result)

    # build_command

    def test_build_command(self):
        cmd = InstalledApplicationList.create_for_device(
            self.enrolled_device
        )
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(payload["RequestType"], "InstalledApplicationList")
        self.assertFalse(payload["ManagedAppsOnly"])

    # process_response

    def test_process_acknowledged_response(self):
        self.assertEqual(self.enrolled_device.blueprint.collect_apps, Blueprint.InventoryItemCollectionOption.ALL)
        start = datetime.utcnow()
        cmd = InstalledApplicationList.create_for_device(
            self.dep_enrollment_session.enrolled_device,
            kwargs={"update_inventory": True}
        )
        cmd.process_response(self.installed_application_list, self.dep_enrollment_session, self.mbu)
        cmd.db_command.refresh_from_db()
        self.assertIsNotNone(cmd.db_command.result)
        self.assertIn("InstalledApplicationList", cmd.response)
        self.enrolled_device.refresh_from_db()
        self.assertTrue(self.enrolled_device.apps_updated_at > start)
        m = MetaMachine(self.enrolled_device.serial_number)
        ms = m.snapshots[0]
        self.assertEqual(ms.osx_app_instances.count(), 3)

    def test_process_acknowledged_response_do_not_collect_apps(self):
        self.blueprint.collect_apps = Blueprint.InventoryItemCollectionOption.NO
        cmd = InstalledApplicationList.create_for_device(
            self.dep_enrollment_session.enrolled_device,
            kwargs={"update_inventory": True}
        )
        cmd.process_response(self.installed_application_list, self.dep_enrollment_session, self.mbu)
        cmd.db_command.refresh_from_db()
        self.assertIsNotNone(cmd.db_command.result)
        self.assertIn("InstalledApplicationList", cmd.response)
        self.enrolled_device.refresh_from_db()
        self.assertIsNone(self.enrolled_device.apps_updated_at)
        m = MetaMachine(self.enrolled_device.serial_number)
        ms = m.snapshots[0]
        self.assertEqual(ms.osx_app_instances.count(), 0)

    # _update_inventory

    def test_update_inventory_do_not_collect_apps_noop(self):
        self.enrolled_device.device_information_updated_at = datetime.utcnow()
        self.enrolled_device.security_info_updated_at = datetime.utcnow()
        self.enrolled_device.blueprint.collect_apps = Blueprint.InventoryItemCollectionOption.NO
        self.assertEqual(self.enrolled_device.blueprint.collect_certificates,
                         Blueprint.InventoryItemCollectionOption.NO)
        self.assertEqual(self.enrolled_device.blueprint.collect_profiles,
                         Blueprint.InventoryItemCollectionOption.NO)
        self.assertIsNone(self.enrolled_device.apps_updated_at)
        self.assertIsNone(_update_inventory(
            Channel.Device, RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            None,
        ))

    def test_update_inventory_managed_apps_updated_at_none(self):
        self.enrolled_device.device_information_updated_at = datetime.utcnow()
        self.enrolled_device.security_info_updated_at = datetime.utcnow()
        self.enrolled_device.blueprint.collect_apps = Blueprint.InventoryItemCollectionOption.MANAGED_ONLY
        self.assertEqual(self.enrolled_device.blueprint.collect_certificates,
                         Blueprint.InventoryItemCollectionOption.NO)
        self.assertEqual(self.enrolled_device.blueprint.collect_profiles,
                         Blueprint.InventoryItemCollectionOption.NO)
        self.assertIsNone(self.enrolled_device.apps_updated_at)
        cmd = _update_inventory(
            Channel.Device, RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            None,
        )
        self.assertIsInstance(cmd, InstalledApplicationList)
        self.assertTrue(cmd.managed_only)
        self.assertTrue(cmd.update_inventory)

    def test_update_inventory_all_apps_updated_at_old(self):
        self.enrolled_device.device_information_updated_at = datetime.utcnow()
        self.enrolled_device.security_info_updated_at = datetime.utcnow()
        self.enrolled_device.blueprint.collect_apps = Blueprint.InventoryItemCollectionOption.ALL
        self.assertEqual(self.enrolled_device.blueprint.collect_certificates,
                         Blueprint.InventoryItemCollectionOption.NO)
        self.assertEqual(self.enrolled_device.blueprint.collect_profiles,
                         Blueprint.InventoryItemCollectionOption.NO)
        self.enrolled_device.apps_updated_at = datetime(2000, 1, 1)
        cmd = _update_inventory(
            Channel.Device, RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            None,
        )
        self.assertIsInstance(cmd, InstalledApplicationList)
        self.assertFalse(cmd.managed_only)
        self.assertTrue(cmd.update_inventory)

    def test_update_inventory_managed_apps_noop(self):
        self.enrolled_device.device_information_updated_at = datetime.utcnow()
        self.enrolled_device.security_info_updated_at = datetime.utcnow()
        self.enrolled_device.blueprint.collect_apps = Blueprint.InventoryItemCollectionOption.MANAGED_ONLY
        self.assertEqual(self.enrolled_device.blueprint.collect_certificates,
                         Blueprint.InventoryItemCollectionOption.NO)
        self.assertEqual(self.enrolled_device.blueprint.collect_profiles,
                         Blueprint.InventoryItemCollectionOption.NO)
        self.enrolled_device.apps_updated_at = datetime.utcnow()
        self.assertIsNone(_update_inventory(
            Channel.Device, RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            None,
        ))
