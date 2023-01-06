import plistlib
from unittest.mock import patch
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import InstallProfile
from zentral.contrib.mdm.commands.scheduling import _install_artifacts
from zentral.contrib.mdm.models import (
    Artifact,
    ArtifactType,
    ArtifactVersion,
    Blueprint,
    BlueprintArtifact,
    Channel,
    DeviceArtifact,
    EnrolledUser,
    Platform,
    Profile,
    RequestStatus,
    SCEPConfig,
    TargetArtifactStatus,
    UserArtifact,
)
from .utils import force_dep_enrollment_session


class InstallProfileCommandTestCase(TestCase):
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
        installed=False,
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
        if installed:
            if channel == Channel.Device:
                DeviceArtifact.objects.create(
                    enrolled_device=self.enrolled_device,
                    artifact_version=artifact_version,
                    status=TargetArtifactStatus.Installed.name,
                )
            else:
                UserArtifact.objects.create(
                    enrolled_user=self.enrolled_user,
                    artifact_version=artifact_version,
                    status=TargetArtifactStatus.Installed.name,
                )
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
                InstallProfile.verify_channel_and_device(channel, self.enrolled_device),
            )

    # build_command

    @patch("zentral.contrib.mdm.commands.install_profile.sign_payload")
    def test_build_command(self, sign_payload):
        sign_payload.side_effect = lambda a: a  # bypass payload signature
        artifact_version, profile = self._force_profile()
        cmd = InstallProfile.create_for_device(self.enrolled_device, artifact_version)
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(payload["RequestType"], "InstallProfile")
        payloadPayload = payload["Payload"]
        loadedPayloadPayload = plistlib.loads(payloadPayload)
        self.assertEqual(
            loadedPayloadPayload,
            {
                "PayloadContent": [],
                "PayloadDisplayName": artifact_version.artifact.name,
                "PayloadIdentifier": f"zentral.artifact.{artifact_version.artifact.pk}",
                "PayloadRemovalDisallowed": False,
                "PayloadType": "Configuration",
                "PayloadUUID": str(artifact_version.pk).upper(),
                "PayloadVersion": 1,
            },
        )
        sign_payload.assert_called_once_with(payloadPayload)

    @patch("zentral.contrib.mdm.commands.install_profile.sign_payload")
    def test_build_command_with_scep_payload_with_variable_substitution(
        self, sign_payload
    ):
        sign_payload.side_effect = lambda a: a  # bypass payload signature
        payload_content = [
            # Name known
            {
                "PayloadContent": {
                    "Name": "YOLO",
                    "Subject": [
                        [["CN", "YOLO"]],
                        [["2.5.4.5", "$ENROLLED_DEVICE.SERIAL_NUMBER"]],
                    ],
                },
                "PayloadIdentifier": "com.example.yolo",
                "PayloadType": "com.apple.security.scep",
                "PayloadUUID": "c0264fd7-1d89-4385-8806-759fbe78a622",
                "PayloadVersion": 1,
            },
            # Name unknown
            {
                "PayloadContent": {
                    "Name": "YOLO2",
                    "Subject": [
                        [["CN", "YOLO2"]],
                        [["2.5.4.5", "$ENROLLED_DEVICE.SERIAL_NUMBER"]],
                    ],
                },
                "PayloadIdentifier": "com.example.yolo2",
                "PayloadType": "com.apple.security.scep",
                "PayloadUUID": "02e788db-d556-43a5-855d-75ce8edd02c2",
                "PayloadVersion": 1,
            },
            # no Name
            {
                "PayloadContent": {
                    "Subject": [
                        [["CN", "YOLO3"]],
                        [["2.5.4.5", "$ENROLLED_DEVICE.SERIAL_NUMBER"]],
                    ],
                },
                "PayloadIdentifier": "com.example.yolo3",
                "PayloadType": "com.apple.security.scep",
                "PayloadUUID": "fa5c34e8-1333-4233-a151-8d376c12e72f",
                "PayloadVersion": 1,
            },
            # no PayloadContent
            {
                "PayloadIdentifier": "com.example.yolo4",
                "PayloadType": "com.apple.security.scep",
                "PayloadUUID": "5e2fcc73-fbe0-4a93-b9f4-bde7a807d44f",
                "PayloadVersion": 1,
            },
        ]
        scep_config = SCEPConfig(
            name="YOLO",
            url="https://example.com/scep",
            challenge_type="STATIC",
        )
        challenge = get_random_string(12)
        scep_config.set_challenge_kwargs({"challenge": challenge})
        scep_config.save()
        artifact_version, profile = self._force_profile(payload_content=payload_content)
        cmd = InstallProfile.create_for_device(self.enrolled_device, artifact_version)
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(payload["RequestType"], "InstallProfile")
        payloadPayload = payload["Payload"]
        loadedPayloadPayload = plistlib.loads(payloadPayload)
        self.assertEqual(
            loadedPayloadPayload,
            {
                "PayloadContent": [
                    # Name known → processed
                    {
                        "PayloadContent": {
                            "Name": "YOLO",
                            "Subject": [
                                [["CN", "YOLO"]],
                                [["2.5.4.5", self.enrolled_device.serial_number]],
                            ],
                            "URL": "https://example.com/scep",
                            "AllowAllAppsAccess": False,
                            "Challenge": challenge,
                            "Key Type": "RSA",
                            "Key Usage": 0,
                            "KeyIsExtractable": False,
                            "Keysize": 2048,
                        },
                        "PayloadIdentifier": "com.example.yolo",
                        "PayloadType": "com.apple.security.scep",
                        "PayloadUUID": "c0264fd7-1d89-4385-8806-759fbe78a622",
                        "PayloadVersion": 1,
                    },
                    # Name unknown → only variable substitution
                    {
                        "PayloadContent": {
                            "Name": "YOLO2",
                            "Subject": [
                                [["CN", "YOLO2"]],
                                [["2.5.4.5", self.enrolled_device.serial_number]],
                            ],
                        },
                        "PayloadIdentifier": "com.example.yolo2",
                        "PayloadType": "com.apple.security.scep",
                        "PayloadUUID": "02e788db-d556-43a5-855d-75ce8edd02c2",
                        "PayloadVersion": 1,
                    },
                    # no Name → only variable substitution
                    {
                        "PayloadContent": {
                            "Subject": [
                                [["CN", "YOLO3"]],
                                [["2.5.4.5", self.enrolled_device.serial_number]],
                            ]
                        },
                        "PayloadIdentifier": "com.example.yolo3",
                        "PayloadType": "com.apple.security.scep",
                        "PayloadUUID": "fa5c34e8-1333-4233-a151-8d376c12e72f",
                        "PayloadVersion": 1,
                    },
                    # no PayloadContent → not processed
                    {
                        "PayloadIdentifier": "com.example.yolo4",
                        "PayloadType": "com.apple.security.scep",
                        "PayloadUUID": "5e2fcc73-fbe0-4a93-b9f4-bde7a807d44f",
                        "PayloadVersion": 1,
                    },
                ],
                "PayloadDisplayName": artifact_version.artifact.name,
                "PayloadIdentifier": f"zentral.artifact.{artifact_version.artifact.pk}",
                "PayloadRemovalDisallowed": False,
                "PayloadType": "Configuration",
                "PayloadUUID": str(artifact_version.pk).upper(),
                "PayloadVersion": 1,
            },
        )
        sign_payload.assert_called_once_with(payloadPayload)

    # process_response

    def test_process_acknowledged_response_device(self):
        artifact_version0, _ = self._force_profile(installed=True)
        artifact_version1, _ = self._force_profile(
            artifact=artifact_version0.artifact, version=1
        )
        qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=artifact_version0.artifact,
        ).order_by("created_at")
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first().artifact_version, artifact_version0)
        cmd = InstallProfile.create_for_device(self.enrolled_device, artifact_version1)
        cmd.process_response(
            {"Status": "Acknowledged"}, self.dep_enrollment_session, self.mbu
        )
        self.assertEqual(qs.count(), 1)
        da = qs.first()
        self.assertEqual(da.artifact_version, artifact_version1)
        self.assertEqual(da.status, TargetArtifactStatus.Installed.name)

    def test_process_acknowledged_response_user(self):
        artifact_version0, _ = self._force_profile(channel=Channel.User, installed=True)
        artifact_version1, _ = self._force_profile(
            channel=Channel.User, artifact=artifact_version0.artifact, version=1
        )
        qs = UserArtifact.objects.filter(
            enrolled_user=self.enrolled_user,
            artifact_version__artifact=artifact_version0.artifact,
        ).order_by("created_at")
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first().artifact_version, artifact_version0)
        cmd = InstallProfile.create_for_user(self.enrolled_user, artifact_version1)
        cmd.process_response(
            {"Status": "Acknowledged"}, self.dep_enrollment_session, self.mbu
        )
        self.assertEqual(qs.count(), 1)
        ua = qs.first()
        self.assertEqual(ua.artifact_version, artifact_version1)
        self.assertEqual(ua.status, TargetArtifactStatus.Installed.name)

    # _install_artifacts

    def test_install_device_profile_already_installed_noop(self):
        artifact_version0, _ = self._force_profile(installed=True)
        self.assertIsNone(
            _install_artifacts(
                Channel.Device,
                RequestStatus.Idle,
                self.dep_enrollment_session,
                self.enrolled_device,
                None,
            )
        )

    def test_install_device_profile_notnow_noop(self):
        artifact_version0, _ = self._force_profile(installed=True)
        artifact_version1, _ = self._force_profile(
            artifact=artifact_version0.artifact, version=1
        )
        self.assertIsNone(_install_artifacts(
            Channel.Device,
            RequestStatus.NotNow,
            self.dep_enrollment_session,
            self.enrolled_device,
            None,
        ))

    def test_install_device_profile_previous_error_noop(self):
        artifact_version, _ = self._force_profile()
        command = _install_artifacts(
            Channel.Device,
            RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            None,
        )
        self.assertIsInstance(command, InstallProfile)
        command.process_response({"Status": "Error", "ErrorChain": [{"un": 1}]},
                                 self.dep_enrollment_session, self.mbu)
        self.assertIsNone(_install_artifacts(
            Channel.Device,
            RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            None,
        ))

    def test_install_device_profile(self):
        artifact_version0, _ = self._force_profile(installed=True)
        artifact_version1, _ = self._force_profile(
            artifact=artifact_version0.artifact, version=1
        )
        cmd = _install_artifacts(
            Channel.Device,
            RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            None,
        )
        self.assertIsInstance(cmd, InstallProfile)
        self.assertEqual(cmd.artifact_version, artifact_version1)

    def test_install_user_profile_already_installed_noop(self):
        artifact_version0, _ = self._force_profile(channel=Channel.User, installed=True)
        self.assertIsNone(
            _install_artifacts(
                Channel.User,
                RequestStatus.Idle,
                self.dep_enrollment_session,
                self.enrolled_device,
                self.enrolled_user,
            )
        )

    def test_install_user_profile_notnow_noop(self):
        artifact_version0, _ = self._force_profile(channel=Channel.User, installed=True)
        artifact_version1, _ = self._force_profile(
            channel=Channel.User, artifact=artifact_version0.artifact, version=1
        )
        self.assertIsNone(_install_artifacts(
            Channel.User,
            RequestStatus.NotNow,
            self.dep_enrollment_session,
            self.enrolled_device,
            self.enrolled_user,
        ))

    def test_install_user_profile_previous_error_noop(self):
        artifact_version, _ = self._force_profile(channel=Channel.User)
        command = _install_artifacts(
            Channel.User,
            RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            self.enrolled_user
        )
        self.assertIsInstance(command, InstallProfile)
        command.process_response({"Status": "Error", "ErrorChain": [{"un": 1}]},
                                 self.dep_enrollment_session, self.mbu)
        self.assertIsNone(_install_artifacts(
            Channel.User,
            RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            self.enrolled_user
        ))

    def test_install_user_profile(self):
        artifact_version0, _ = self._force_profile(channel=Channel.User, installed=True)
        artifact_version1, _ = self._force_profile(
            channel=Channel.User, artifact=artifact_version0.artifact, version=1
        )
        cmd = _install_artifacts(
            Channel.User,
            RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            self.enrolled_user,
        )
        self.assertIsInstance(cmd, InstallProfile)
        self.assertEqual(cmd.artifact_version, artifact_version1)
