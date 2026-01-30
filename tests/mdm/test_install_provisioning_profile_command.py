import plistlib
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import InstallProvisioningProfile
from zentral.contrib.mdm.commands.scheduling import _install_artifacts
from zentral.contrib.mdm.models import (
    Artifact,
    Blueprint,
    Channel,
    DeviceArtifact,
    Platform,
    RequestStatus,
    TargetArtifact,
)
from zentral.contrib.mdm.utils import get_provisioning_profile_info
from .utils import force_artifact, force_blueprint_artifact, force_dep_enrollment_session


class InstallProvisioningProfileCommandTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.dep_enrollment_session, _, _ = force_dep_enrollment_session(
            cls.mbu, authenticated=True, completed=True, realm_user=True
        )
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device
        cls.blueprint = Blueprint.objects.create(name=get_random_string(12))
        cls.enrolled_device.blueprint = cls.blueprint
        cls.enrolled_device.save()

    # verify_channel_and_device

    def test_scope(self):
        for channel, platform, user_enrollment, result in (
            (Channel.DEVICE, Platform.IOS, False, True),
            (Channel.DEVICE, Platform.IPADOS, False, True),
            (Channel.DEVICE, Platform.MACOS, False, True),
            (Channel.DEVICE, Platform.TVOS, False, True),
            (Channel.USER, Platform.IOS, False, False),
            (Channel.USER, Platform.IPADOS, False, False),
            (Channel.USER, Platform.MACOS, False, False),
            (Channel.USER, Platform.TVOS, False, False),
            (Channel.DEVICE, Platform.IOS, True, True),
            (Channel.DEVICE, Platform.IPADOS, True, True),
            (Channel.DEVICE, Platform.MACOS, True, True),
            (Channel.DEVICE, Platform.TVOS, True, True),
            (Channel.USER, Platform.IOS, True, False),
            (Channel.USER, Platform.IPADOS, True, False),
            (Channel.USER, Platform.MACOS, True, False),
            (Channel.USER, Platform.TVOS, True, False),
        ):
            self.enrolled_device.platform = platform
            self.enrolled_device.user_enrollment = user_enrollment
            self.assertEqual(
                result,
                InstallProvisioningProfile.verify_channel_and_device(channel, self.enrolled_device),
            )

    # build_command

    def test_build_command(self):
        _, (artifact_version,) = force_artifact(artifact_type=Artifact.Type.PROVISIONING_PROFILE)
        artifact_version.refresh_from_db()  # to make sure we get a memoryview which is not serializable in a plist
        self.assertIsInstance(artifact_version.provisioning_profile.source, memoryview)
        cmd = InstallProvisioningProfile.create_for_device(self.enrolled_device, artifact_version)
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(payload["RequestType"], "InstallProvisioningProfile")
        provisioning_profile = artifact_version.provisioning_profile
        name, pp_uuid, content = get_provisioning_profile_info(payload["ProvisioningProfile"])
        self.assertEqual(provisioning_profile.name, name)
        self.assertEqual(provisioning_profile.uuid, pp_uuid)
        self.assertEqual(str(provisioning_profile.uuid), plistlib.loads(content)["UUID"])

    # process_response

    def test_process_acknowledged_response_device(self):
        artifact, (av2, av1) = force_artifact(
            artifact_type=Artifact.Type.PROVISIONING_PROFILE,
            version_count=2,
        )
        DeviceArtifact.objects.create(
            enrolled_device=self.enrolled_device,
            artifact_version=av1,
            status=TargetArtifact.Status.ACKNOWLEDGED,
        )
        cmd = InstallProvisioningProfile.create_for_device(self.enrolled_device, av2)
        cmd.process_response(
            {"Status": "Acknowledged"}, self.dep_enrollment_session, self.mbu
        )
        qs = DeviceArtifact.objects.filter(enrolled_device=self.enrolled_device, artifact_version__artifact=artifact)
        self.assertEqual(qs.count(), 1)
        da = qs.first()
        self.assertEqual(da.artifact_version, av2)
        self.assertEqual(da.status, TargetArtifact.Status.ACKNOWLEDGED)

    # _install_artifacts

    def test_install_device_provisioning_profile_already_installed_noop(self):
        _, _, (av1,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.PROVISIONING_PROFILE,
            blueprint=self.blueprint,
        )
        DeviceArtifact.objects.create(
            enrolled_device=self.enrolled_device,
            artifact_version=av1,
            status=TargetArtifact.Status.ACKNOWLEDGED,
        )
        self.assertIsNone(
            _install_artifacts(
                Target(self.enrolled_device),
                self.dep_enrollment_session,
                RequestStatus.IDLE,
            )
        )

    def test_install_device_provisioning_profile_notnow_noop(self):
        _, _, (av1,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.PROVISIONING_PROFILE,
            blueprint=self.blueprint,
        )
        self.assertIsNone(_install_artifacts(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.NOT_NOW,
        ))

    def test_install_device_provisioning_profile_previous_error_noop(self):
        _, _, (av1,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.PROVISIONING_PROFILE,
            blueprint=self.blueprint,
        )
        command = _install_artifacts(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(command, InstallProvisioningProfile)
        command.process_response({"Status": "Error", "ErrorChain": [{"un": 1}]},
                                 self.dep_enrollment_session, self.mbu)
        self.assertIsNone(_install_artifacts(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_install_device_provisioning_profile(self):
        _, _, (av2, av1) = force_blueprint_artifact(
            artifact_type=Artifact.Type.PROVISIONING_PROFILE,
            blueprint=self.blueprint,
            version_count=2,
        )
        DeviceArtifact.objects.create(
            enrolled_device=self.enrolled_device,
            artifact_version=av1,
            status=TargetArtifact.Status.ACKNOWLEDGED,
        )
        cmd = _install_artifacts(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, InstallProvisioningProfile)
        self.assertEqual(cmd.artifact_version, av2)
