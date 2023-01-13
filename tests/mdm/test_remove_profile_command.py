import plistlib
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import RemoveProfile
from zentral.contrib.mdm.commands.scheduling import _remove_artifacts
from zentral.contrib.mdm.models import (
    Artifact,
    ArtifactType,
    ArtifactVersion,
    Channel,
    Blueprint,
    BlueprintArtifact,
    DeviceArtifact,
    EnrolledUser,
    Platform,
    Profile,
    RequestStatus,
    TargetArtifactStatus,
    UserArtifact,
)
from .utils import force_dep_enrollment_session


class RemoveProfileCommandTestCase(TestCase):
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
        cls.enrolled_user = EnrolledUser.objects.create(
            enrolled_device=cls.enrolled_device,
            user_id=str(uuid.uuid4()).upper(),
            long_name=get_random_string(12),
            short_name=get_random_string(12),
            token=get_random_string(12).encode("utf-8"),
        )

    def _force_profile(
        self,
        channel=Channel.Device,
        artifact=None,
        version=None,
        payload_content=None,
        status=None,
        in_blueprint=False,
    ):
        if artifact is None:
            artifact_name = get_random_string(12)
            artifact = Artifact.objects.create(
                name=artifact_name,
                type=ArtifactType.Profile.name,
                channel=channel.name,
                platforms=[Platform.macOS.name],
            )
        else:
            artifact_name = artifact.name
        artifact_version = ArtifactVersion.objects.create(
            artifact=artifact, version=version or 0
        )
        try:
            payload_identifier = (
                artifact.artifactversion_set.first().profile.payload_identifier
            )
        except Exception:
            payload_identifier = str(uuid.uuid4())
        profile = Profile.objects.create(
            artifact_version=artifact_version,
            filename=f"{artifact_name}.mobileconfig",
            source=plistlib.dumps(
                {
                    "PayloadContent": payload_content if payload_content else [],
                    "PayloadDisplayName": artifact_name,
                    "PayloadIdentifier": payload_identifier,
                    "PayloadRemovalDisallowed": False,
                    "PayloadType": "Configuration",
                    "PayloadUUID": str(uuid.uuid4()),
                    "PayloadVersion": 1,
                }
            ),
            payload_identifier=payload_identifier,
            payload_display_name=artifact_name,
            payload_description="",
        )
        if status:
            if channel == Channel.Device:
                DeviceArtifact.objects.create(
                    enrolled_device=self.enrolled_device,
                    artifact_version=artifact_version,
                    status=status.name,
                )
            else:
                UserArtifact.objects.create(
                    enrolled_user=self.enrolled_user,
                    artifact_version=artifact_version,
                    status=status.name,
                )
        if in_blueprint:
            BlueprintArtifact.objects.create(
                blueprint=self.blueprint,
                artifact=artifact,
                install_before_setup_assistant=False,
                auto_update=True,
                priority=100,
            )
        return artifact_version, profile

    # verify_channel_and_device

    def test_scope(self):
        for channel, platform, user_enrollment, result in (
            (Channel.Device, Platform.iOS, False, True),
            (Channel.Device, Platform.iPadOS, False, True),
            (Channel.Device, Platform.macOS, False, True),
            (Channel.Device, Platform.tvOS, False, True),
            (Channel.User, Platform.iOS, False, False),
            (Channel.User, Platform.iPadOS, False, True),
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
                RemoveProfile.verify_channel_and_device(channel, self.enrolled_device),
            )

    # build_command

    def test_build_command(self):
        artifact_version, profile = self._force_profile()
        cmd = RemoveProfile.create_for_device(self.enrolled_device, artifact_version)
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(
            payload,
            {
                "RequestType": "RemoveProfile",
                "Identifier": f"zentral.artifact.{artifact_version.artifact.pk}",
            },
        )

    # process_response

    def test_process_acknowledged_response_device(self):
        artifact_version, _ = self._force_profile(status=TargetArtifactStatus.Installed)
        qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=artifact_version.artifact,
        )
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first().artifact_version, artifact_version)
        cmd = RemoveProfile.create_for_device(self.enrolled_device, artifact_version)
        cmd.process_response(
            {"Status": "Acknowledged"}, self.dep_enrollment_session, self.mbu
        )
        self.assertEqual(qs.count(), 0)

    def test_process_acknowledged_response_user(self):
        artifact_version, _ = self._force_profile(
            channel=Channel.User, status=TargetArtifactStatus.Installed
        )
        qs = UserArtifact.objects.filter(
            enrolled_user=self.enrolled_user,
            artifact_version__artifact=artifact_version.artifact,
        )
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first().artifact_version, artifact_version)
        cmd = RemoveProfile.create_for_user(self.enrolled_user, artifact_version)
        cmd.process_response(
            {"Status": "Acknowledged"}, self.dep_enrollment_session, self.mbu
        )
        self.assertEqual(qs.count(), 0)

    # _remove_artifacts

    def test_remove_device_profile_noop(self):
        artifact_version, _ = self._force_profile(
            status=TargetArtifactStatus.Installed, in_blueprint=True
        )
        self.assertIsNone(
            _remove_artifacts(
                Channel.Device,
                RequestStatus.Idle,
                self.dep_enrollment_session,
                self.enrolled_device,
                None,
            )
        )

    def test_remove_device_profile_notnow_noop(self):
        artifact_version, _ = self._force_profile(status=TargetArtifactStatus.Installed)
        self.assertIsNone(
            _remove_artifacts(
                Channel.Device,
                RequestStatus.NotNow,
                self.dep_enrollment_session,
                self.enrolled_device,
                None,
            )
        )

    def test_remove_device_profile(self):
        self.assertFalse(self.enrolled_device.declarative_management)
        artifact_version, _ = self._force_profile(status=TargetArtifactStatus.Installed)
        command = _remove_artifacts(
            Channel.Device,
            RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            None,
        )
        self.assertIsInstance(command, RemoveProfile)
        self.assertEqual(command.channel, Channel.Device)
        self.assertEqual(command.artifact_version, artifact_version)

    def test_remove_device_profile_declarative_management_noop(self):
        self.enrolled_device.declarative_management = True
        artifact_version, _ = self._force_profile(status=TargetArtifactStatus.Installed)
        self.assertIsNone(_remove_artifacts(
            Channel.Device,
            RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            None,
        ))

    def test_remove_device_profile_previous_error_noop(self):
        self._force_profile(status=TargetArtifactStatus.Installed)
        command = _remove_artifacts(
            Channel.Device,
            RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            None,
        )
        command.process_response(
            {"Status": "Error", "ErrorChain": [{"un": 1}]},
            self.dep_enrollment_session,
            self.mbu,
        )
        self.assertIsNone(
            _remove_artifacts(
                Channel.Device,
                RequestStatus.Idle,
                self.dep_enrollment_session,
                self.enrolled_device,
                None,
            )
        )

    def test_remove_user_profile_noop(self):
        artifact_version, _ = self._force_profile(
            channel=Channel.User,
            status=TargetArtifactStatus.Installed,
            in_blueprint=True,
        )
        self.assertIsNone(
            _remove_artifacts(
                Channel.User,
                RequestStatus.Idle,
                self.dep_enrollment_session,
                self.enrolled_device,
                self.enrolled_user,
            )
        )

    def test_remove_user_profile_notnow_noop(self):
        artifact_version, _ = self._force_profile(
            channel=Channel.User, status=TargetArtifactStatus.Installed
        )
        self.assertIsNone(
            _remove_artifacts(
                Channel.User,
                RequestStatus.NotNow,
                self.dep_enrollment_session,
                self.enrolled_device,
                self.enrolled_user,
            )
        )

    def test_remove_user_profile(self):
        self.assertFalse(self.enrolled_device.declarative_management)
        artifact_version, _ = self._force_profile(
            channel=Channel.User, status=TargetArtifactStatus.Installed
        )
        command = _remove_artifacts(
            Channel.User,
            RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            self.enrolled_user,
        )
        self.assertIsInstance(command, RemoveProfile)
        self.assertEqual(command.channel, Channel.User)
        self.assertEqual(command.artifact_version, artifact_version)

    def test_remove_user_profile_declarative_management(self):
        self.enrolled_device.declarative_management = True
        artifact_version, _ = self._force_profile(
            channel=Channel.User, status=TargetArtifactStatus.Installed
        )
        command = _remove_artifacts(
            Channel.User,
            RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            self.enrolled_user,
        )
        self.assertIsInstance(command, RemoveProfile)
        self.assertEqual(command.channel, Channel.User)
        self.assertEqual(command.artifact_version, artifact_version)

    def test_remove_user_profile_previous_error_noop(self):
        self._force_profile(channel=Channel.User, status=TargetArtifactStatus.Installed)
        command = _remove_artifacts(
            Channel.User,
            RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            self.enrolled_user,
        )
        command.process_response(
            {"Status": "Error", "ErrorChain": [{"un": 1}]},
            self.dep_enrollment_session,
            self.mbu,
        )
        self.assertIsNone(
            _remove_artifacts(
                Channel.User,
                RequestStatus.Idle,
                self.dep_enrollment_session,
                self.enrolled_device,
                self.enrolled_user,
            )
        )
