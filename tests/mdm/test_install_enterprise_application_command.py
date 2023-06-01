import plistlib
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target, update_blueprint_serialized_artifacts
from zentral.contrib.mdm.commands import InstalledApplicationList, InstallEnterpriseApplication
from zentral.contrib.mdm.commands.base import load_command
from zentral.contrib.mdm.commands.scheduling import _install_artifacts
from zentral.contrib.mdm.models import (Artifact, ArtifactVersion,
                                        Blueprint, BlueprintArtifact, Channel,
                                        DeviceArtifact, DeviceCommand, EnterpriseApp,
                                        Platform, RequestStatus, TargetArtifact)
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
            type=Artifact.Type.ENTERPRISE_APP,
            channel=Channel.DEVICE,
            platforms=[Platform.MACOS],
            auto_update=True,
        )
        cls.artifact_version0 = ArtifactVersion.objects.create(
            artifact=cls.artifact,
            version=0,
            macos=True,
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
            status=TargetArtifact.Status.INSTALLED
        )
        BlueprintArtifact.objects.get_or_create(
            blueprint=cls.blueprint,
            artifact=cls.artifact,
            defaults={"macos": True},
        )
        cls.artifact_version = ArtifactVersion.objects.create(
            artifact=cls.artifact,
            version=1,
            macos=True
        )
        cls.enterprise_app = EnterpriseApp.objects.create(
            artifact_version=cls.artifact_version,
            filename="yolo.pkg",
            product_id="com.example.enterprise-app",
            product_version="1.0.0",
            manifest={"items": [{"assets": [{}]}]}
        )
        update_blueprint_serialized_artifacts(cls.blueprint)

    # verify_channel_and_device

    def test_scope(self):
        for channel, platform, user_enrollment, result in (
            (Channel.DEVICE, Platform.IOS, False, False),
            (Channel.DEVICE, Platform.IPADOS, False, False),
            (Channel.DEVICE, Platform.MACOS, False, True),
            (Channel.DEVICE, Platform.TVOS, False, False),
            (Channel.USER, Platform.IOS, False, False),
            (Channel.USER, Platform.IPADOS, False, False),
            (Channel.USER, Platform.MACOS, False, False),
            (Channel.USER, Platform.TVOS, False, False),
            (Channel.DEVICE, Platform.IOS, True, False),
            (Channel.DEVICE, Platform.IPADOS, True, False),
            (Channel.DEVICE, Platform.MACOS, True, True),
            (Channel.DEVICE, Platform.TVOS, True, False),
        ):
            self.enrolled_device.platform = platform
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

    def test_build_managed_command_remove_on_unenroll_macos_11(self):
        self.enrolled_device.os_version = "11.6.1"
        self.enterprise_app.install_as_managed = True
        self.enterprise_app.remove_on_unenroll = True
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
             "InstallAsManaged": True,
             "ChangeManagementState": "Managed",
             "ManagementFlags": 1}
        )

    def test_build_managed_do_not_remove_on_unenroll_macos_11(self):
        self.enrolled_device.os_version = "11.6.1"
        self.enterprise_app.install_as_managed = True
        self.enterprise_app.remove_on_unenroll = False
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
             "InstallAsManaged": True,
             "ChangeManagementState": "Managed",
             "ManagementFlags": 0}
        )

    def test_build_managed_configuration(self):
        self.enterprise_app.configuration = plistlib.dumps({"Yolo": "Fomo $ENROLLED_DEVICE.SERIAL_NUMBER"})
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
             "Configuration": {
                "Yolo": f"Fomo {self.enrolled_device.serial_number}"
             }}
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
        self.assertEqual(da1.status, TargetArtifact.Status.AWAITING_CONFIRMATION)
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
        self.assertEqual(da.status, TargetArtifact.Status.ACKNOWLEDGED)
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
            artifact_version__artifact=self.artifact,
            status=TargetArtifact.Status.INSTALLED,
        ).update(artifact_version=self.artifact_version)
        self.assertIsNone(_install_artifacts(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_install_artifacts(self):
        cmd = _install_artifacts(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, InstallEnterpriseApplication)
        self.assertEqual(cmd.artifact_version, self.artifact_version)
