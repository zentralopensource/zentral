import plistlib
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target, update_blueprint_serialized_artifacts
from zentral.contrib.mdm.commands import RemoveProfile
from zentral.contrib.mdm.commands.scheduling import _remove_artifacts
from zentral.contrib.mdm.models import (
    Artifact,
    ArtifactVersion,
    Channel,
    Blueprint,
    BlueprintArtifact,
    DeviceArtifact,
    EnrolledUser,
    Platform,
    Profile,
    RequestStatus,
    TargetArtifact,
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
        channel=Channel.DEVICE,
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
                type=Artifact.Type.PROFILE,
                channel=channel,
                platforms=[Platform.MACOS],
                auto_update=True,
            )
        else:
            artifact_name = artifact.name
        artifact_version = ArtifactVersion.objects.create(
            artifact=artifact, version=version or 0, macos=True,
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
            if channel == Channel.DEVICE:
                DeviceArtifact.objects.create(
                    enrolled_device=self.enrolled_device,
                    artifact_version=artifact_version,
                    status=status,
                )
            else:
                UserArtifact.objects.create(
                    enrolled_user=self.enrolled_user,
                    artifact_version=artifact_version,
                    status=status,
                )
        if in_blueprint:
            BlueprintArtifact.objects.get_or_create(
                blueprint=self.blueprint,
                artifact=artifact,
                defaults={"macos": True},
            )
            update_blueprint_serialized_artifacts(self.blueprint)
        return artifact_version, profile

    # verify_channel_and_device

    def test_scope(self):
        for channel, platform, user_enrollment, result in (
            (Channel.DEVICE, Platform.IOS, False, True),
            (Channel.DEVICE, Platform.IPADOS, False, True),
            (Channel.DEVICE, Platform.MACOS, False, True),
            (Channel.DEVICE, Platform.TVOS, False, True),
            (Channel.USER, Platform.IOS, False, False),
            (Channel.USER, Platform.IPADOS, False, True),
            (Channel.USER, Platform.MACOS, False, True),
            (Channel.USER, Platform.TVOS, False, False),
            (Channel.DEVICE, Platform.IOS, True, True),
            (Channel.DEVICE, Platform.IPADOS, True, False),
            (Channel.DEVICE, Platform.MACOS, True, True),
            (Channel.DEVICE, Platform.TVOS, True, False),
            (Channel.USER, Platform.IOS, True, False),
            (Channel.USER, Platform.IPADOS, True, False),
            (Channel.USER, Platform.MACOS, True, True),
            (Channel.USER, Platform.TVOS, True, False),
        ):
            self.enrolled_device.platform = platform
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
        artifact_version, _ = self._force_profile(status=TargetArtifact.Status.INSTALLED)
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
        self.assertEqual(qs.count(), 1)
        ta = qs.first()
        self.assertEqual(ta.status, TargetArtifact.Status.UNINSTALLED)

    def test_process_acknowledged_response_user(self):
        artifact_version, _ = self._force_profile(
            channel=Channel.USER, status=TargetArtifact.Status.INSTALLED
        )
        qs = UserArtifact.objects.filter(
            enrolled_user=self.enrolled_user,
            artifact_version__artifact=artifact_version.artifact,
        )
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first().artifact_version, artifact_version)
        cmd = RemoveProfile.create_for_target(
            Target(self.enrolled_device, self.enrolled_user),
            artifact_version
        )
        cmd.process_response(
            {"Status": "Acknowledged"}, self.dep_enrollment_session, self.mbu
        )
        self.assertEqual(qs.count(), 1)
        ta = qs.first()
        self.assertEqual(ta.status, TargetArtifact.Status.UNINSTALLED)

    # _remove_artifacts

    def test_remove_device_profile_noop(self):
        artifact_version, _ = self._force_profile(
            status=TargetArtifact.Status.INSTALLED, in_blueprint=True
        )
        self.assertIsNone(
            _remove_artifacts(
                Target(self.enrolled_device),
                self.dep_enrollment_session,
                RequestStatus.IDLE,
            )
        )

    def test_remove_device_profile_notnow_noop(self):
        artifact_version, _ = self._force_profile(status=TargetArtifact.Status.INSTALLED)
        self.assertIsNone(
            _remove_artifacts(
                Target(self.enrolled_device),
                self.dep_enrollment_session,
                RequestStatus.NOT_NOW,
            )
        )

    def test_remove_device_profile(self):
        self.assertFalse(self.enrolled_device.declarative_management)
        artifact_version, _ = self._force_profile(status=TargetArtifact.Status.INSTALLED)
        command = _remove_artifacts(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(command, RemoveProfile)
        self.assertEqual(command.channel, Channel.DEVICE)
        self.assertEqual(command.artifact_version, artifact_version)

    def test_remove_device_profile_declarative_management_noop(self):
        self.enrolled_device.declarative_management = True
        artifact_version, _ = self._force_profile(status=TargetArtifact.Status.INSTALLED)
        self.assertIsNone(_remove_artifacts(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_remove_device_profile_previous_error_noop(self):
        self._force_profile(status=TargetArtifact.Status.INSTALLED)
        command = _remove_artifacts(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        command.process_response(
            {"Status": "Error", "ErrorChain": [{"un": 1}]},
            self.dep_enrollment_session,
            self.mbu,
        )
        self.assertIsNone(
            _remove_artifacts(
                Target(self.enrolled_device),
                self.dep_enrollment_session,
                RequestStatus.IDLE,
            )
        )

    def test_remove_user_profile_noop(self):
        artifact_version, _ = self._force_profile(
            channel=Channel.USER,
            status=TargetArtifact.Status.INSTALLED,
            in_blueprint=True,
        )
        self.assertIsNone(
            _remove_artifacts(
                Target(self.enrolled_device, self.enrolled_user),
                self.dep_enrollment_session,
                RequestStatus.IDLE,
            )
        )

    def test_remove_user_profile_notnow_noop(self):
        artifact_version, _ = self._force_profile(
            channel=Channel.USER, status=TargetArtifact.Status.INSTALLED
        )
        self.assertIsNone(
            _remove_artifacts(
                Target(self.enrolled_device, self.enrolled_user),
                self.dep_enrollment_session,
                RequestStatus.NOT_NOW,
            )
        )

    def test_remove_user_profile(self):
        self.assertFalse(self.enrolled_device.declarative_management)
        artifact_version, _ = self._force_profile(
            channel=Channel.USER, status=TargetArtifact.Status.INSTALLED
        )
        command = _remove_artifacts(
            Target(self.enrolled_device, self.enrolled_user),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(command, RemoveProfile)
        self.assertEqual(command.channel, Channel.USER)
        self.assertEqual(command.artifact_version, artifact_version)

    def test_remove_user_profile_declarative_management(self):
        self.enrolled_device.declarative_management = True
        artifact_version, _ = self._force_profile(
            channel=Channel.USER, status=TargetArtifact.Status.INSTALLED
        )
        command = _remove_artifacts(
            Target(self.enrolled_device, self.enrolled_user),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(command, RemoveProfile)
        self.assertEqual(command.channel, Channel.USER)
        self.assertEqual(command.artifact_version, artifact_version)

    def test_remove_user_profile_previous_error_noop(self):
        self._force_profile(channel=Channel.USER, status=TargetArtifact.Status.INSTALLED)
        command = _remove_artifacts(
            Target(self.enrolled_device, self.enrolled_user),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        command.process_response(
            {"Status": "Error", "ErrorChain": [{"un": 1}]},
            self.dep_enrollment_session,
            self.mbu,
        )
        self.assertIsNone(
            _remove_artifacts(
                Target(self.enrolled_device, self.enrolled_user),
                self.dep_enrollment_session,
                RequestStatus.IDLE,
            )
        )
