from datetime import datetime
import os.path
import plistlib
from unittest.mock import call, patch
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit, MetaMachine
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import InstalledApplicationList
from zentral.contrib.mdm.commands.scheduling import _update_extra_inventory, load_command
from zentral.contrib.mdm.models import (Artifact, Blueprint, Channel,
                                        DeviceArtifact, DeviceCommand, Platform,
                                        RequestStatus, TargetArtifact)
from .utils import force_blueprint_artifact, force_dep_enrollment_session


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
        with open(os.path.join(os.path.dirname(__file__), "testdata/installed_application_list.plist"), "rb") as f:
            cls.installed_application_list = plistlib.load(f)

    # verify_channel_and_device

    def test_scope(self):
        for channel, platform, user_enrollment, result in (
            (Channel.DEVICE, Platform.IOS, False, True),
            (Channel.DEVICE, Platform.IPADOS, False, True),
            (Channel.DEVICE, Platform.MACOS, False, True),
            (Channel.DEVICE, Platform.TVOS, False, True),
            (Channel.USER, Platform.IOS, False, False),
            (Channel.USER, Platform.IPADOS, False, False),
            (Channel.USER, Platform.MACOS, False, True),
            (Channel.USER, Platform.TVOS, False, False),
            (Channel.DEVICE, Platform.IOS, True, True),
            (Channel.DEVICE, Platform.IPADOS, True, True),
            (Channel.DEVICE, Platform.MACOS, True, False),
            (Channel.DEVICE, Platform.TVOS, True, False),
            (Channel.USER, Platform.IOS, True, False),
            (Channel.USER, Platform.IPADOS, True, False),
            (Channel.USER, Platform.MACOS, True, False),
            (Channel.USER, Platform.TVOS, True, False),
        ):
            self.enrolled_device.platform = platform
            self.enrolled_device.user_enrollment = user_enrollment
            self.assertEqual(
                result,
                InstalledApplicationList.verify_channel_and_device(channel, self.enrolled_device),
            )

    # load_kwargs

    def test_load_kwargs_defaults(self):
        cmd = InstalledApplicationList.create_for_target(
            Target(self.enrolled_device),
        )
        self.assertFalse(cmd.managed_only)
        self.assertFalse(cmd.update_inventory)
        self.assertTrue(cmd.store_result)

    def test_load_kwargs(self):
        cmd = InstalledApplicationList.create_for_target(
            Target(self.enrolled_device),
            kwargs={"managed_only": True,
                    "update_inventory": True}
        )
        self.assertTrue(cmd.managed_only)
        self.assertTrue(cmd.update_inventory)
        self.assertTrue(cmd.store_result)

    # build_command

    def test_build_command(self):
        cmd = InstalledApplicationList.create_for_target(
            Target(self.enrolled_device)
        )
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(
            payload,
            {'Items': ['AdHocCodeSigned',
                       'AppStoreVendable',
                       'BetaApp',
                       'BundleSize',
                       'DeviceBasedVPP',
                       'DynamicSize',
                       'ExternalVersionIdentifier',
                       'HasUpdateAvailable',
                       'Identifier',
                       'Installing',
                       'IsAppClip',
                       'IsValidated',
                       'Name',
                       'ShortVersion',
                       'Version'],
             'ManagedAppsOnly': False,
             'RequestType': 'InstalledApplicationList'}
        )

    def test_build_command_apps_to_check(self):
        _, _, [artifact_version] = force_blueprint_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP,
                                                            blueprint=self.blueprint)
        cmd = InstalledApplicationList.create_for_target(
            Target(self.enrolled_device),
            artifact_version,
            kwargs={"apps_to_check": [{"Identifier": "yolo.fomo", "ShortVersion": "1.0"}]}
        )
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(payload["RequestType"], "InstalledApplicationList")
        self.assertEqual(
            payload,
            {'Identifiers': ['yolo.fomo'],
             'Items': ['AdHocCodeSigned',
                       'AppStoreVendable',
                       'BetaApp',
                       'BundleSize',
                       'DeviceBasedVPP',
                       'DynamicSize',
                       'ExternalVersionIdentifier',
                       'HasUpdateAvailable',
                       'Identifier',
                       'Installing',
                       'IsAppClip',
                       'IsValidated',
                       'Name',
                       'ShortVersion',
                       'Version'],
             'ManagedAppsOnly': False,
             'RequestType': 'InstalledApplicationList'}
        )

    # process_response

    def test_process_acknowledged_response(self):
        self.assertEqual(self.enrolled_device.blueprint.collect_apps, Blueprint.InventoryItemCollectionOption.ALL)
        start = datetime.utcnow()
        cmd = InstalledApplicationList.create_for_target(
            Target(self.dep_enrollment_session.enrolled_device),
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
        cmd = InstalledApplicationList.create_for_target(
            Target(self.dep_enrollment_session.enrolled_device),
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

    # _update_extra_inventory

    def test_update_extra_inventory_do_not_collect_apps_noop(self):
        self.enrolled_device.device_information_updated_at = datetime.utcnow()
        self.enrolled_device.security_info_updated_at = datetime.utcnow()
        self.enrolled_device.blueprint.collect_apps = Blueprint.InventoryItemCollectionOption.NO
        self.assertEqual(self.enrolled_device.blueprint.collect_certificates,
                         Blueprint.InventoryItemCollectionOption.NO)
        self.assertEqual(self.enrolled_device.blueprint.collect_profiles,
                         Blueprint.InventoryItemCollectionOption.NO)
        self.assertIsNone(self.enrolled_device.apps_updated_at)
        self.assertIsNone(_update_extra_inventory(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_update_extra_inventory_managed_apps_updated_at_none(self):
        self.enrolled_device.device_information_updated_at = datetime.utcnow()
        self.enrolled_device.security_info_updated_at = datetime.utcnow()
        self.enrolled_device.blueprint.collect_apps = Blueprint.InventoryItemCollectionOption.MANAGED_ONLY
        self.assertEqual(self.enrolled_device.blueprint.collect_certificates,
                         Blueprint.InventoryItemCollectionOption.NO)
        self.assertEqual(self.enrolled_device.blueprint.collect_profiles,
                         Blueprint.InventoryItemCollectionOption.NO)
        self.assertIsNone(self.enrolled_device.apps_updated_at)
        cmd = _update_extra_inventory(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, InstalledApplicationList)
        self.assertTrue(cmd.managed_only)
        self.assertTrue(cmd.update_inventory)

    def test_update_extra_inventory_all_apps_updated_at_old(self):
        self.enrolled_device.device_information_updated_at = datetime.utcnow()
        self.enrolled_device.security_info_updated_at = datetime.utcnow()
        self.enrolled_device.blueprint.collect_apps = Blueprint.InventoryItemCollectionOption.ALL
        self.assertEqual(self.enrolled_device.blueprint.collect_certificates,
                         Blueprint.InventoryItemCollectionOption.NO)
        self.assertEqual(self.enrolled_device.blueprint.collect_profiles,
                         Blueprint.InventoryItemCollectionOption.NO)
        self.enrolled_device.apps_updated_at = datetime(2000, 1, 1)
        cmd = _update_extra_inventory(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, InstalledApplicationList)
        self.assertFalse(cmd.managed_only)
        self.assertTrue(cmd.update_inventory)

    def test_update_extra_inventory_managed_apps_noop(self):
        self.enrolled_device.device_information_updated_at = datetime.utcnow()
        self.enrolled_device.security_info_updated_at = datetime.utcnow()
        self.enrolled_device.blueprint.collect_apps = Blueprint.InventoryItemCollectionOption.MANAGED_ONLY
        self.assertEqual(self.enrolled_device.blueprint.collect_certificates,
                         Blueprint.InventoryItemCollectionOption.NO)
        self.assertEqual(self.enrolled_device.blueprint.collect_profiles,
                         Blueprint.InventoryItemCollectionOption.NO)
        self.enrolled_device.apps_updated_at = datetime.utcnow()
        self.assertIsNone(_update_extra_inventory(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    # _update_device_artifact

    @patch("zentral.contrib.mdm.commands.installed_application_list.logger")
    def test_update_device_artifact_not_found_new_command(self, logger):
        _, artifact, [artifact_version] = force_blueprint_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP,
                                                                   blueprint=self.blueprint)
        target = Target(self.enrolled_device)
        target.update_target_artifact(
            artifact_version,
            TargetArtifact.Status.AWAITING_CONFIRMATION
        )
        cmd = InstalledApplicationList.create_for_target(
            target,
            artifact_version,
            kwargs={"apps_to_check": [{"Identifier": "yolo.fomo", "ShortVersion": "1.0"}]},
            queue=False,
        )
        cmd.process_response(
            {"Status": "Acknowledged",
             "InstalledApplicationList": []},
            self.dep_enrollment_session,
            self.mbu
        )
        qs = DeviceCommand.objects.filter(
            enrolled_device=self.enrolled_device,
            time__isnull=True
        )
        self.assertEqual(qs.count(), 1)
        new_cmd = load_command(qs.first())
        self.assertIsInstance(new_cmd, InstalledApplicationList)
        self.assertEqual(new_cmd.artifact_version, artifact_version)
        self.assertEqual(new_cmd.retries, 1)
        self.assertEqual(new_cmd.apps_to_check, [{"Identifier": "yolo.fomo", "ShortVersion": "1.0"}])
        logger.warning.assert_called_once_with("Artifact version %s was not found.", artifact_version.pk)

    @patch("zentral.contrib.mdm.commands.installed_application_list.logger")
    def test_update_device_artifact_not_found_too_many_retries(self, logger):
        _, artifact, [artifact_version] = force_blueprint_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP,
                                                                   blueprint=self.blueprint)
        target = Target(self.enrolled_device)
        target.update_target_artifact(
            artifact_version,
            TargetArtifact.Status.AWAITING_CONFIRMATION
        )
        cmd = InstalledApplicationList.create_for_target(
            target,
            artifact_version,
            kwargs={"apps_to_check": [{"Identifier": "yolo.fomo", "ShortVersion": "1.0"}],
                    "retries": 10},
            queue=False,
        )
        cmd.process_response(
            {"Status": "Acknowledged",
             "InstalledApplicationList": []},
            self.dep_enrollment_session,
            self.mbu
        )
        qs = DeviceCommand.objects.filter(
            enrolled_device=self.enrolled_device,
            time__isnull=True
        )
        self.assertEqual(qs.count(), 0)
        logger.warning.assert_has_calls(
            [call("Artifact version %s was not found.", artifact_version.pk),
             call("Stop rescheduling %s command for artifact version %s", cmd.request_type, artifact_version.pk)]
        )

    def test_update_device_artifact_installing_new_command(self):
        _, artifact, [artifact_version] = force_blueprint_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP,
                                                                   blueprint=self.blueprint)
        target = Target(self.enrolled_device)
        target.update_target_artifact(
            artifact_version,
            TargetArtifact.Status.AWAITING_CONFIRMATION
        )
        cmd = InstalledApplicationList.create_for_target(
            target,
            artifact_version,
            kwargs={"apps_to_check": [{"Identifier": "yolo.fomo", "ShortVersion": "1.0"}],
                    "retries": 1},
            queue=False,
        )
        cmd.process_response(
            {"Status": "Acknowledged",
             "InstalledApplicationList": [
                 {"Identifier": "yolo.fomo",
                  "ShortVersion": "1.0",
                  "Installing": True}
             ]},
            self.dep_enrollment_session,
            self.mbu
        )
        qs = DeviceCommand.objects.filter(
            enrolled_device=self.enrolled_device,
            time__isnull=True
        )
        self.assertEqual(qs.count(), 1)
        new_cmd = load_command(qs.first())
        self.assertIsInstance(new_cmd, InstalledApplicationList)
        self.assertEqual(new_cmd.artifact_version, artifact_version)
        self.assertEqual(new_cmd.retries, 2)
        self.assertEqual(new_cmd.apps_to_check, [{"Identifier": "yolo.fomo", "ShortVersion": "1.0"}])
        da = DeviceArtifact.objects.get(enrolled_device=self.enrolled_device, artifact_version=artifact_version)
        self.assertEqual(da.status, TargetArtifact.Status.AWAITING_CONFIRMATION)

    def test_update_device_artifact_failed(self):
        _, artifact, [artifact_version] = force_blueprint_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP,
                                                                   blueprint=self.blueprint)
        target = Target(self.enrolled_device)
        target.update_target_artifact(
            artifact_version,
            TargetArtifact.Status.AWAITING_CONFIRMATION
        )
        cmd = InstalledApplicationList.create_for_target(
            target,
            artifact_version,
            kwargs={"apps_to_check": [{"Identifier": "yolo.fomo", "ShortVersion": "1.0"}]},
            queue=False,
        )
        cmd.process_response(
            {"Status": "Acknowledged",
             "InstalledApplicationList": [
                {"Identifier": "not.a.match",
                 "ShortVersion": "1.0",
                 "Installing": False},
                {"Identifier": "yolo.fomo",
                 "ShortVersion": "1.0",
                 "Installing": True,
                 "DownloadFailed": True}
             ]},
            self.dep_enrollment_session,
            self.mbu
        )
        qs = DeviceCommand.objects.filter(
            enrolled_device=self.enrolled_device,
            time__isnull=True
        )
        self.assertEqual(qs.count(), 0)
        da = DeviceArtifact.objects.get(enrolled_device=self.enrolled_device, artifact_version=artifact_version)
        self.assertEqual(da.status, TargetArtifact.Status.FAILED)

    def test_update_device_artifact_installed(self):
        _, artifact, [artifact_version] = force_blueprint_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP,
                                                                   blueprint=self.blueprint)
        target = Target(self.enrolled_device)
        target.update_target_artifact(
            artifact_version,
            TargetArtifact.Status.AWAITING_CONFIRMATION
        )
        cmd = InstalledApplicationList.create_for_target(
            target,
            artifact_version,
            kwargs={"apps_to_check": [{"Identifier": "yolo.fomo", "ShortVersion": "1.0"}]},
            queue=False,
        )
        cmd.process_response(
            {"Status": "Acknowledged",
             "InstalledApplicationList": [
                {"Identifier": "not.a.match",
                 "ShortVersion": "1.0",
                 "Installing": False},
                {"Identifier": "yolo.fomo",
                 "ShortVersion": "1.0",
                 "Installing": False}
             ]},
            self.dep_enrollment_session,
            self.mbu
        )
        qs = DeviceCommand.objects.filter(
            enrolled_device=self.enrolled_device,
            time__isnull=True
        )
        self.assertEqual(qs.count(), 0)
        da = DeviceArtifact.objects.get(enrolled_device=self.enrolled_device, artifact_version=artifact_version)
        self.assertEqual(da.status, TargetArtifact.Status.INSTALLED)
