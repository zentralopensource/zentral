import plistlib
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import InstalledApplicationList, InstallEnterpriseApplication
from zentral.contrib.mdm.commands.base import load_command
from zentral.contrib.mdm.commands.scheduling import _install_artifacts
from zentral.contrib.mdm.models import (Artifact, ArtifactType, ArtifactVersion,
                                        Blueprint, BlueprintArtifact, Channel,
                                        DeviceArtifact, DeviceCommand, EnterpriseApp,
                                        Platform, RequestStatus, TargetArtifactStatus)
from .utils import force_dep_enrollment_session


class InstallEnterpriseApplicationCommandTestCase(TestCase):
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
        cls.blueprint = Blueprint.objects.create(name=get_random_string(12))
        cls.enrolled_device.blueprint = cls.blueprint
        cls.enrolled_device.save()
        cls.artifact = Artifact.objects.create(
            name=get_random_string(32),
            type=ArtifactType.EnterpriseApp.name,
            channel=Channel.Device.name,
            platforms=[Platform.macOS.name],
        )
        cls.artifact_version0 = ArtifactVersion.objects.create(
            artifact=cls.artifact,
            version=0
        )
        cls.enterprise_app = EnterpriseApp.objects.create(
            artifact_version=cls.artifact_version0,
            filename="yolo.pkg",
            product_id="com.example.enterprise-app",
            product_version="0.0.0",
            manifest={"items": [{"assets": [{}]}]}
        )
        DeviceArtifact.objects.create(
            enrolled_device=cls.enrolled_device,
            artifact_version=cls.artifact_version0,
            status=TargetArtifactStatus.Installed.name
        )
        BlueprintArtifact.objects.create(
            blueprint=cls.blueprint,
            artifact=cls.artifact,
            install_before_setup_assistant=True,
            auto_update=True,
            priority=100
        )
        cls.artifact_version = ArtifactVersion.objects.create(
            artifact=cls.artifact,
            version=1
        )
        cls.enterprise_app = EnterpriseApp.objects.create(
            artifact_version=cls.artifact_version,
            filename="yolo.pkg",
            product_id="com.example.enterprise-app",
            product_version="1.0.0",
            manifest={"items": [{"assets": [{}]}]}
        )

    # verify_channel_and_device

    def test_scope(self):
        for channel, platform, user_enrollment, result in (
            (Channel.Device, Platform.iOS, False, False),
            (Channel.Device, Platform.iPadOS, False, False),
            (Channel.Device, Platform.macOS, False, True),
            (Channel.Device, Platform.tvOS, False, False),
            (Channel.User, Platform.iOS, False, False),
            (Channel.User, Platform.iPadOS, False, False),
            (Channel.User, Platform.macOS, False, False),
            (Channel.User, Platform.tvOS, False, False),
            (Channel.Device, Platform.iOS, True, False),
            (Channel.Device, Platform.iPadOS, True, False),
            (Channel.Device, Platform.macOS, True, True),
            (Channel.Device, Platform.tvOS, True, False),
        ):
            self.enrolled_device.platform = platform.name
            self.enrolled_device.user_enrollment = user_enrollment
            self.assertEqual(
                result,
                InstallEnterpriseApplication.verify_channel_and_device(
                    channel, self.enrolled_device
                )
            )

    # build_command

    def test_build_command(self):
        self.assertIsNone(self.enrolled_device.os_version)
        cmd = InstallEnterpriseApplication.create_for_device(self.enrolled_device, self.artifact_version)
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(
            payload,
            {"RequestType": "InstallEnterpriseApplication",
             "Manifest": {
                 "items": [
                     {"assets": [
                         {"url": f"https://zentral/mdm/device_commands/{cmd.uuid}/enterprise_app/"}
                      ]}
                 ]
             }}
        )

    def test_build_command_macos_11(self):
        self.enrolled_device.os_version = "11.6.1"
        cmd = InstallEnterpriseApplication.create_for_device(self.enrolled_device, self.artifact_version)
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(
            payload,
            {"RequestType": "InstallEnterpriseApplication",
             "Manifest": {
                 "items": [
                     {"assets": [
                         {"url": f"https://zentral/mdm/device_commands/{cmd.uuid}/enterprise_app/"}
                      ]}
                 ]
             },
             "InstallAsManaged": False}
        )

    # process_response

    def test_process_acknowledged_response_with_bundles(self):
        qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=self.artifact
        ).order_by("created_at")
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first().artifact_version, self.artifact_version0)
        self.enterprise_app.bundles = [
            {"id": "com.example.enterprise-app.yolo1", "version_str": "1.0.0"}
        ]
        cmd = InstallEnterpriseApplication.create_for_device(self.enrolled_device, self.artifact_version)
        cmd.process_response(
            {"Status": "Acknowledged"},
            self.dep_enrollment_session,
            self.mbu
        )
        self.assertEqual(qs.count(), 2)
        da0, da1 = list(qs)
        self.assertEqual(da0.artifact_version, self.artifact_version0)
        self.assertEqual(da1.artifact_version, self.artifact_version)
        self.assertEqual(da1.status, TargetArtifactStatus.AwaitingConfirmation.name)
        qs = DeviceCommand.objects.filter(
            enrolled_device=self.enrolled_device,
            time__isnull=True
        )
        self.assertEqual(qs.count(), 1)
        db_cmd = qs.first()
        cmd = load_command(db_cmd)
        self.assertIsInstance(cmd, InstalledApplicationList)
        self.assertEqual(cmd.artifact_version, self.artifact_version)
        self.assertEqual(
            cmd.apps_to_check,
            [{"Identifier": "com.example.enterprise-app.yolo1", "ShortVersion": "1.0.0"}]
        )

    def test_process_acknowledged_response_without_bundles(self):
        qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=self.artifact
        ).order_by("created_at")
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first().artifact_version, self.artifact_version0)
        cmd = InstallEnterpriseApplication.create_for_device(self.enrolled_device, self.artifact_version)
        cmd.process_response(
            {"Status": "Acknowledged"},
            self.dep_enrollment_session,
            self.mbu
        )
        self.assertEqual(qs.count(), 1)
        da = qs.first()
        self.assertEqual(da.artifact_version, self.artifact_version)
        self.assertEqual(da.status, TargetArtifactStatus.Acknowledged.name)
        self.assertEqual(
            DeviceCommand.objects.filter(
                enrolled_device=self.enrolled_device,
                time__isnull=True
            ).count(),
            0
        )

    # _install_artifacts

    def test_install_artifacts_noop(self):
        DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=self.artifact
        ).update(artifact_version=self.artifact_version)
        self.assertIsNone(_install_artifacts(
            Channel.Device, RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            None
        ))

    def test_install_artifacts(self):
        cmd = _install_artifacts(
            Channel.Device, RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            None
        )
        self.assertIsInstance(cmd, InstallEnterpriseApplication)
        self.assertEqual(cmd.artifact_version, self.artifact_version)
