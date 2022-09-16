from datetime import datetime
import os.path
import plistlib
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit, MetaMachine
from zentral.contrib.mdm.commands import InstalledApplicationList
from zentral.contrib.mdm.inventory import commit_update_tree, tree_from_payload
from zentral.contrib.mdm.models import Blueprint
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
        cls.device_information = plistlib.load(
            open(os.path.join(os.path.dirname(__file__),
                              "testdata/device_information.plist"),
                 "rb")
        )
        cls.device_information["UDID"] = cls.enrolled_device.udid
        cls.device_information["SerialNumber"] = cls.enrolled_device.serial_number
        cls.installed_application_list = plistlib.load(
            open(os.path.join(os.path.dirname(__file__),
                              "testdata/installed_application_list.plist"),
                 "rb")
        )

    def test_load_kwargs_store_result_false(self):
        cmd = InstalledApplicationList.create_for_device(
            self.enrolled_device,
            kwargs={"managed_only": True,
                    "update_inventory": True}
        )
        self.assertTrue(cmd.managed_only)
        self.assertTrue(cmd.update_inventory)
        self.assertFalse(cmd.store_result)

    def test_load_kwargs_store_result_true(self):
        cmd = InstalledApplicationList.create_for_device(
            self.enrolled_device,
        )
        self.assertFalse(cmd.managed_only)
        self.assertFalse(cmd.update_inventory)
        self.assertTrue(cmd.store_result)

    def test_build_command(self):
        cmd = InstalledApplicationList.create_for_device(
            self.enrolled_device
        )
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(payload["RequestType"], "InstalledApplicationList")
        self.assertFalse(payload["ManagedAppsOnly"])

    def test_process_acknowledged_response_missing_cms(self):
        cmd = InstalledApplicationList.create_for_device(
            self.dep_enrollment_session.enrolled_device,
            kwargs={"update_inventory": True}
        )
        cmd.process_response(self.installed_application_list, self.dep_enrollment_session, self.mbu)
        cmd.db_command.refresh_from_db()
        self.assertIsNone(cmd.db_command.result)
        self.enrolled_device.refresh_from_db()
        self.assertIsNone(self.enrolled_device.apps_updated_at)
        m = MetaMachine(self.enrolled_device.serial_number)
        self.assertEqual(len(m.snapshots), 0)

    def test_process_acknowledged_response_do_not_collect_apps(self):
        start = datetime.utcnow()
        ms_tree = tree_from_payload(
            self.enrolled_device.udid,
            self.enrolled_device.serial_number,
            self.mbu,
            self.device_information["QueryResponses"]
        )
        commit_update_tree(self.enrolled_device, ms_tree, missing_ok=True)
        m0 = MetaMachine(self.enrolled_device.serial_number)
        ms0 = m0.snapshots[0]
        self.assertEqual(ms0.osx_app_instances.count(), 0)
        cmd = InstalledApplicationList.create_for_device(
            self.dep_enrollment_session.enrolled_device,
            kwargs={"update_inventory": True}
        )
        self.blueprint.collect_apps = Blueprint.InventoryItemCollectionOption.NO
        self.blueprint.save()
        cmd.process_response(self.installed_application_list, self.dep_enrollment_session, self.mbu)
        cmd.db_command.refresh_from_db()
        self.assertIsNone(cmd.db_command.result)
        self.enrolled_device.refresh_from_db()
        self.assertTrue(self.enrolled_device.apps_updated_at > start)
        m = MetaMachine(self.enrolled_device.serial_number)
        ms = m.snapshots[0]
        self.assertEqual(ms.osx_app_instances.count(), 0)

    def test_process_acknowledged_response_collect_apps(self):
        start = datetime.utcnow()
        ms_tree = tree_from_payload(
            self.enrolled_device.udid,
            self.enrolled_device.serial_number,
            self.mbu,
            self.device_information["QueryResponses"]
        )
        commit_update_tree(self.enrolled_device, ms_tree, missing_ok=True)
        m0 = MetaMachine(self.enrolled_device.serial_number)
        ms0 = m0.snapshots[0]
        self.assertEqual(ms0.osx_app_instances.count(), 0)
        cmd = InstalledApplicationList.create_for_device(
            self.dep_enrollment_session.enrolled_device,
            kwargs={"update_inventory": True}
        )
        self.assertEqual(self.enrolled_device.blueprint.collect_apps, Blueprint.InventoryItemCollectionOption.ALL)
        cmd.process_response(self.installed_application_list, self.dep_enrollment_session, self.mbu)
        cmd.db_command.refresh_from_db()
        self.assertIsNone(cmd.db_command.result)
        self.enrolled_device.refresh_from_db()
        self.assertTrue(self.enrolled_device.apps_updated_at > start)
        m = MetaMachine(self.enrolled_device.serial_number)
        ms = m.snapshots[0]
        self.assertEqual(ms.osx_app_instances.count(), 3)
