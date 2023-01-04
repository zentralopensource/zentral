import copy
import os.path
import plistlib
from unittest.mock import patch
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import ManagedApplicationList
from zentral.contrib.mdm.commands.utils import load_command
from zentral.contrib.mdm.models import (
    Artifact,
    ArtifactType,
    ArtifactVersion,
    Asset,
    Blueprint,
    BlueprintArtifact,
    Channel,
    DeviceArtifact,
    DeviceCommand,
    Platform,
    StoreApp,
    TargetArtifactStatus,
)
from .utils import force_dep_enrollment_session


class ManagedApplicationListCommandTestCase(TestCase):
    maxDiff = None

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
        )
        cls.enrolled_device.blueprint = cls.blueprint
        cls.enrolled_device.save()
        cls.device_information = plistlib.load(
            open(
                os.path.join(
                    os.path.dirname(__file__), "testdata/device_information.plist"
                ),
                "rb",
            )
        )
        cls.device_information["UDID"] = cls.enrolled_device.udid
        cls.device_information["SerialNumber"] = cls.enrolled_device.serial_number
        cls.managed_application_list = plistlib.load(
            open(
                os.path.join(
                    os.path.dirname(__file__), "testdata/managed_application_list.plist"
                ),
                "rb",
            )
        )

    def _get_response(self, cmd, status=None):
        response = copy.deepcopy(self.managed_application_list)
        response["CommandUUID"] = str(cmd.db_command.uuid).upper()
        response["UDID"] = self.enrolled_device.udid
        if status:
            response["ManagedApplicationList"]["com.acme.myenterpriseapp"]["Status"] = status
        return response

    def _force_store_app(self, artifact=None, bundle_id=None, version=None, status=None):
        if artifact is None:
            artifact = Artifact.objects.create(
                name=get_random_string(32),
                type=ArtifactType.StoreApp.name,
                channel=Channel.Device.name,
                platforms=[Platform.macOS.name],
            )
            asset = Asset.objects.create(
                adam_id="1234567890",
                pricing_param="STDQ",
                bundle_id=bundle_id or "com.acme.myenterpriseapp",
                product_type=Asset.ProductType.APP,
                device_assignable=True,
                revocable=True,
                supported_platforms=[Platform.macOS.name],
            )
        else:
            asset = artifact.artifactversion_set.first().store_app.asset
        artifact_version = ArtifactVersion.objects.create(
            artifact=artifact, version=version or 0
        )
        store_app = StoreApp.objects.create(
            artifact_version=artifact_version, asset=asset
        )
        if status:
            DeviceArtifact.objects.create(
                enrolled_device=self.enrolled_device,
                artifact_version=artifact_version,
                status=status.name,
            )
        BlueprintArtifact.objects.create(
            blueprint=self.blueprint,
            artifact=artifact,
            install_before_setup_assistant=False,
            auto_update=True,
            priority=100,
        )
        return artifact_version, store_app

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
            (Channel.Device, Platform.macOS, True, True),
            (Channel.Device, Platform.tvOS, True, False),
            (Channel.User, Platform.iOS, True, False),
            (Channel.User, Platform.iPadOS, True, False),
            (Channel.User, Platform.macOS, True, True),
            (Channel.User, Platform.tvOS, True, False),
        ):
            self.enrolled_device.platform = platform.name
            self.enrolled_device.user_enrollment = user_enrollment
            self.assertEqual(
                result,
                ManagedApplicationList.verify_channel_and_device(
                    channel, self.enrolled_device
                ),
            )

    # load_kwargs

    def test_load_kwargs_store_result_false(self):
        artifact_version, store_app = self._force_store_app()
        cmd = ManagedApplicationList.create_for_device(
            self.enrolled_device,
            artifact_version,
            kwargs={"identifiers": [store_app.asset.bundle_id]}
        )
        self.assertEqual(cmd.identifiers, [store_app.asset.bundle_id])
        self.assertEqual(cmd.retries, 0)
        self.assertFalse(cmd.store_result)

    def test_load_kwargs_store_result_true(self):
        cmd = ManagedApplicationList.create_for_device(
            self.enrolled_device,
        )
        self.assertEqual(cmd.identifiers, [])
        self.assertEqual(cmd.retries, 0)
        self.assertTrue(cmd.store_result)

    # build_command

    def test_build_command(self):
        cmd = ManagedApplicationList.create_for_device(
            self.enrolled_device,
        )
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(payload["RequestType"], "ManagedApplicationList")
        self.assertNotIn("Identifiers", payload)

    def test_build_command_with_identifiers(self):
        artifact_version, store_app = self._force_store_app()
        cmd = ManagedApplicationList.create_for_device(
            self.enrolled_device,
            artifact_version,
            kwargs={"identifiers": [store_app.asset.bundle_id]}
        )
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(payload["RequestType"], "ManagedApplicationList")
        self.assertEqual(payload["Identifiers"], [store_app.asset.bundle_id])

    # process_response

    def test_process_acknowledged_response_stored_result(self):
        cmd = ManagedApplicationList.create_for_device(
            self.enrolled_device,
        )
        response = self._get_response(cmd)
        cmd.process_response(response, self.dep_enrollment_session, self.mbu)
        cmd.db_command.refresh_from_db()
        result = plistlib.loads(cmd.db_command.result)
        self.assertEqual(
            result,
            {
                "CommandUUID": str(cmd.db_command.uuid).upper(),
                "ManagedApplicationList": {
                    "com.acme.myenterpriseapp": {
                        "ExternalVersionIdentifier": 0,
                        "HasConfiguration": False,
                        "HasFeedback": False,
                        "IsValidated": True,
                        "ManagementFlags": 0,
                        "Status": "Managed",
                    }
                },
                "Status": "Acknowledged",
                "UDID": self.enrolled_device.udid,
            },
        )

    def test_update_device_artifact_found_and_installed(self):
        artifact_version0, _ = self._force_store_app(status=TargetArtifactStatus.Installed)
        artifact_version, store_app = self._force_store_app(
            artifact=artifact_version0.artifact,
            version=1,
            status=TargetArtifactStatus.AwaitingConfirmation
        )
        da_qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=artifact_version0.artifact
        )
        self.assertEqual(da_qs.count(), 2)
        cmd = ManagedApplicationList.create_for_device(
            self.enrolled_device,
            artifact_version,
            kwargs={"identifiers": [store_app.asset.bundle_id]}
        )
        response = self._get_response(cmd, status="Managed")
        cmd.process_response(response, self.dep_enrollment_session, self.mbu)
        self.assertEqual(da_qs.count(), 1)
        da = da_qs.first()
        self.assertEqual(da.artifact_version, artifact_version)
        self.assertEqual(da.status, TargetArtifactStatus.Installed.name)
        dcmd_qs = DeviceCommand.objects.filter(
            enrolled_device=self.enrolled_device,
            time__isnull=True
        )
        self.assertEqual(dcmd_qs.count(), 0)

    def test_update_device_artifact_error(self):
        artifact_version0, _ = self._force_store_app(status=TargetArtifactStatus.Installed)
        artifact_version, store_app = self._force_store_app(
            artifact=artifact_version0.artifact,
            version=1,
            status=TargetArtifactStatus.AwaitingConfirmation
        )
        da_qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=artifact_version0.artifact
        )
        self.assertEqual(da_qs.count(), 2)
        cmd = ManagedApplicationList.create_for_device(
            self.enrolled_device,
            artifact_version,
            kwargs={"identifiers": [store_app.asset.bundle_id]}
        )
        response = self._get_response(cmd, status="Failed")
        cmd.process_response(response, self.dep_enrollment_session, self.mbu)
        self.assertEqual(da_qs.count(), 1)
        da = da_qs.first()
        self.assertEqual(da.artifact_version, artifact_version0)
        self.assertEqual(da.status, TargetArtifactStatus.Installed.name)
        dcmd_qs = DeviceCommand.objects.filter(
            enrolled_device=self.enrolled_device,
            time__isnull=True
        )
        self.assertEqual(dcmd_qs.count(), 0)

    @patch("zentral.contrib.mdm.commands.managed_application_list.logger.warning")
    def test_update_device_artifact_not_found(self, logger_warning):
        artifact_version, store_app = self._force_store_app(
            bundle_id="com.example.yolo",
            status=TargetArtifactStatus.AwaitingConfirmation
        )
        da_qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=artifact_version.artifact
        )
        self.assertEqual(da_qs.count(), 1)
        da = da_qs.first()
        self.assertEqual(da.artifact_version, artifact_version)
        self.assertEqual(da.status, TargetArtifactStatus.AwaitingConfirmation.name)
        cmd = ManagedApplicationList.create_for_device(
            self.enrolled_device,
            artifact_version,
            kwargs={"identifiers": [store_app.asset.bundle_id]}
        )
        self.assertEqual(cmd.retries, 0)
        response = self._get_response(cmd, status="Managed")
        cmd.process_response(response, self.dep_enrollment_session, self.mbu)
        self.assertEqual(da_qs.count(), 1)
        da = da_qs.first()
        self.assertEqual(da.artifact_version, artifact_version)
        self.assertEqual(da.status, TargetArtifactStatus.AwaitingConfirmation.name)
        logger_warning.assert_called_once_with(
            "Artifact version %s was not found on device %s.",
            artifact_version.pk, self.enrolled_device.serial_number
        )
        dcmd_qs = DeviceCommand.objects.filter(
            enrolled_device=self.enrolled_device,
            time__isnull=True
        )
        self.assertEqual(dcmd_qs.count(), 1)
        cmd = load_command(dcmd_qs.first())
        self.assertIsInstance(cmd, ManagedApplicationList)
        self.assertEqual(cmd.artifact_version, artifact_version)
        self.assertEqual(cmd.identifiers, [store_app.asset.bundle_id])
        self.assertEqual(cmd.retries, 1)

    @patch("zentral.contrib.mdm.commands.managed_application_list.logger.warning")
    def test_update_device_artifact_found_not_installed_no_error(self, logger_warning):
        artifact_version, store_app = self._force_store_app(
            status=TargetArtifactStatus.AwaitingConfirmation
        )
        da_qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=artifact_version.artifact
        )
        self.assertEqual(da_qs.count(), 1)
        da = da_qs.first()
        self.assertEqual(da.artifact_version, artifact_version)
        self.assertEqual(da.status, TargetArtifactStatus.AwaitingConfirmation.name)
        cmd = ManagedApplicationList.create_for_device(
            self.enrolled_device,
            artifact_version,
            kwargs={"identifiers": [store_app.asset.bundle_id]}
        )
        self.assertEqual(cmd.retries, 0)
        response = self._get_response(cmd, status="Installing")
        cmd.process_response(response, self.dep_enrollment_session, self.mbu)
        self.assertEqual(da_qs.count(), 1)
        da = da_qs.first()
        self.assertEqual(da.artifact_version, artifact_version)
        self.assertEqual(da.status, TargetArtifactStatus.AwaitingConfirmation.name)
        logger_warning.assert_not_called()
        dcmd_qs = DeviceCommand.objects.filter(
            enrolled_device=self.enrolled_device,
            time__isnull=True
        )
        self.assertEqual(dcmd_qs.count(), 1)
        cmd = load_command(dcmd_qs.first())
        self.assertIsInstance(cmd, ManagedApplicationList)
        self.assertEqual(cmd.artifact_version, artifact_version)
        self.assertEqual(cmd.identifiers, [store_app.asset.bundle_id])
        self.assertEqual(cmd.retries, 1)

    @patch("zentral.contrib.mdm.commands.managed_application_list.logger.warning")
    def test_update_device_artifact_found_not_installed_no_error_too_many_retries(self, logger_warning):
        artifact_version, store_app = self._force_store_app(
            bundle_id="com.example.yolo",
            status=TargetArtifactStatus.AwaitingConfirmation
        )
        da_qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=artifact_version.artifact
        )
        self.assertEqual(da_qs.count(), 1)
        da = da_qs.first()
        self.assertEqual(da.artifact_version, artifact_version)
        self.assertEqual(da.status, TargetArtifactStatus.AwaitingConfirmation.name)
        cmd = ManagedApplicationList.create_for_device(
            self.enrolled_device,
            artifact_version,
            kwargs={"identifiers": [store_app.asset.bundle_id],
                    "retries": 10}
        )
        self.assertEqual(cmd.retries, 10)
        response = self._get_response(cmd, status="Managed")
        cmd.process_response(response, self.dep_enrollment_session, self.mbu)
        self.assertEqual(da_qs.count(), 1)
        da = da_qs.first()
        self.assertEqual(da.artifact_version, artifact_version)
        self.assertEqual(da.status, TargetArtifactStatus.AwaitingConfirmation.name)
        logger_warning.assert_called_once_with(
            "Stop rescheduling %s command on device %s for artifact version %s.",
            "ManagedApplicationList", self.enrolled_device.serial_number, artifact_version.pk
        )
        dcmd_qs = DeviceCommand.objects.filter(
            enrolled_device=self.enrolled_device,
            time__isnull=True
        )
        self.assertEqual(dcmd_qs.count(), 0)
