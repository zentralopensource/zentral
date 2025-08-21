import plistlib
from unittest.mock import patch
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target, update_blueprint_serialized_artifacts
from zentral.contrib.mdm.commands import InstallProfile
from zentral.contrib.mdm.commands.scheduling import _install_artifacts
from zentral.contrib.mdm.models import (
    Artifact,
    ArtifactVersion,
    Blueprint,
    BlueprintArtifact,
    Channel,
    DeviceArtifact,
    EnrolledUser,
    Platform,
    Profile,
    RequestStatus,
    SCEPIssuer,
    TargetArtifact,
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
        channel=Channel.DEVICE,
        artifact=None,
        version=None,
        payload_content=None,
        installed=False,
    ):
        if artifact is None:
            artifact_name = get_random_string(12)
            artifact = Artifact.objects.create(
                name=artifact_name,
                type=Artifact.Type.PROFILE,
                channel=channel,
                platforms=[Platform.MACOS],
            )
        else:
            artifact_name = artifact.name
        artifact_version = ArtifactVersion.objects.create(
            artifact=artifact,
            version=version or 0,
            macos=True,
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
            if channel == Channel.DEVICE:
                DeviceArtifact.objects.create(
                    enrolled_device=self.enrolled_device,
                    artifact_version=artifact_version,
                    status=TargetArtifact.Status.INSTALLED,
                )
            else:
                UserArtifact.objects.create(
                    enrolled_user=self.enrolled_user,
                    artifact_version=artifact_version,
                    status=TargetArtifact.Status.INSTALLED,
                )
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
            (Channel.DEVICE, Platform.IPADOS, True, True),
            (Channel.DEVICE, Platform.MACOS, True, True),
            (Channel.DEVICE, Platform.TVOS, True, False),
            (Channel.USER, Platform.IOS, True, False),
            (Channel.USER, Platform.IPADOS, True, True),
            (Channel.USER, Platform.MACOS, True, True),
            (Channel.USER, Platform.TVOS, True, False),
        ):
            self.enrolled_device.platform = platform
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
                    "AllowAllAppsAccess": True,
                    "KeyIsExtractable": False,
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
        scep_issuer = SCEPIssuer(
            name="YOLO",
            url="https://example.com/scep",
            backend="STATIC_CHALLENGE",
        )
        challenge = get_random_string(12)
        scep_issuer.set_backend_kwargs({"challenge": challenge})
        scep_issuer.save()
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
                            "AllowAllAppsAccess": True,
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
        self.assertEqual(da.status, TargetArtifact.Status.ACKNOWLEDGED)

    def test_process_acknowledged_response_user(self):
        artifact_version0, _ = self._force_profile(channel=Channel.USER, installed=True)
        artifact_version1, _ = self._force_profile(
            channel=Channel.USER, artifact=artifact_version0.artifact, version=1
        )
        qs = UserArtifact.objects.filter(
            enrolled_user=self.enrolled_user,
            artifact_version__artifact=artifact_version0.artifact,
        ).order_by("created_at")
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first().artifact_version, artifact_version0)
        cmd = InstallProfile.create_for_target(Target(self.enrolled_device, self.enrolled_user), artifact_version1)
        cmd.process_response(
            {"Status": "Acknowledged"}, self.dep_enrollment_session, self.mbu
        )
        self.assertEqual(qs.count(), 1)
        ua = qs.first()
        self.assertEqual(ua.artifact_version, artifact_version1)
        self.assertEqual(ua.status, TargetArtifact.Status.ACKNOWLEDGED)

    # _install_artifacts

    def test_install_device_profile_already_installed_noop(self):
        artifact_version0, _ = self._force_profile(installed=True)
        self.assertIsNone(
            _install_artifacts(
                Target(self.enrolled_device),
                self.dep_enrollment_session,
                RequestStatus.IDLE,
            )
        )

    def test_install_device_profile_notnow_noop(self):
        artifact_version0, _ = self._force_profile(installed=True)
        artifact_version1, _ = self._force_profile(
            artifact=artifact_version0.artifact, version=1
        )
        self.assertIsNone(_install_artifacts(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.NOT_NOW,
        ))

    def test_install_device_profile_previous_error_noop(self):
        artifact_version, _ = self._force_profile()
        command = _install_artifacts(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(command, InstallProfile)
        command.process_response({"Status": "Error", "ErrorChain": [{"un": 1}]},
                                 self.dep_enrollment_session, self.mbu)
        self.assertIsNone(_install_artifacts(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_install_device_profile(self):
        self.assertFalse(self.enrolled_device.declarative_management)
        artifact_version0, _ = self._force_profile(installed=True)
        artifact_version1, _ = self._force_profile(
            artifact=artifact_version0.artifact, version=1
        )
        cmd = _install_artifacts(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, InstallProfile)
        self.assertEqual(cmd.artifact_version, artifact_version1)

    def test_install_device_profile_declarative_management_no_legacy_profiles(self):
        self.enrolled_device.declarative_management = True
        self.assertTrue(Artifact.Type.PROFILE not in Target(self.enrolled_device).ddm_managed_artifact_types())
        artifact_version, _ = self._force_profile()
        cmd = _install_artifacts(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, InstallProfile)
        self.assertEqual(cmd.artifact_version, artifact_version)

    @patch("zentral.contrib.mdm.artifacts.Target.ddm_managed_artifact_types")
    def test_install_device_profile_declarative_management_noop(self, ddm_managed_artifact_types):
        # force inclusion of the PROFILE
        ddm_managed_artifact_types.return_value = tuple(t for t in Artifact.Type if t.is_declaration)
        self.enrolled_device.declarative_management = True
        artifact_version, _ = self._force_profile()
        self.assertIsNone(_install_artifacts(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_install_user_profile_already_installed_noop(self):
        artifact_version0, _ = self._force_profile(channel=Channel.USER, installed=True)
        self.assertIsNone(
            _install_artifacts(
                Target(self.enrolled_device, self.enrolled_user),
                self.dep_enrollment_session,
                RequestStatus.IDLE,
            )
        )

    def test_install_user_profile_notnow_noop(self):
        artifact_version0, _ = self._force_profile(channel=Channel.USER, installed=True)
        artifact_version1, _ = self._force_profile(
            channel=Channel.USER, artifact=artifact_version0.artifact, version=1
        )
        self.assertIsNone(_install_artifacts(
            Target(self.enrolled_device, self.enrolled_user),
            self.dep_enrollment_session,
            RequestStatus.NOT_NOW,
        ))

    def test_install_user_profile_previous_error_noop(self):
        artifact_version, _ = self._force_profile(channel=Channel.USER)
        command = _install_artifacts(
            Target(self.enrolled_device, self.enrolled_user),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(command, InstallProfile)
        command.process_response({"Status": "Error", "ErrorChain": [{"un": 1}]},
                                 self.dep_enrollment_session, self.mbu)
        self.assertIsNone(_install_artifacts(
            Target(self.enrolled_device, self.enrolled_user),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_install_user_profile(self):
        self.assertFalse(self.enrolled_device.declarative_management)
        artifact_version0, _ = self._force_profile(channel=Channel.USER, installed=True)
        artifact_version1, _ = self._force_profile(
            channel=Channel.USER, artifact=artifact_version0.artifact, version=1
        )
        cmd = _install_artifacts(
            Target(self.enrolled_device, self.enrolled_user),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, InstallProfile)
        self.assertEqual(cmd.artifact_version, artifact_version1)

    def test_install_user_profile_declarative_management(self):
        self.enrolled_device.declarative_management = True
        artifact_version0, _ = self._force_profile(channel=Channel.USER, installed=True)
        artifact_version1, _ = self._force_profile(
            channel=Channel.USER, artifact=artifact_version0.artifact, version=1
        )
        cmd = _install_artifacts(
            Target(self.enrolled_device, self.enrolled_user),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, InstallProfile)
        self.assertEqual(cmd.artifact_version, artifact_version1)
