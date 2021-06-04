import copy
import plistlib
import uuid
from datetime import datetime
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.models import (Artifact, ArtifactOperation, ArtifactType, ArtifactVersion,
                                        Blueprint, BlueprintArtifact,
                                        Channel, DeviceArtifact, DeviceCommand,
                                        EnrolledDevice, EnrolledUser,
                                        Platform, Profile, PushCertificate,
                                        UserArtifact, UserCommand)


PROFILE_TEMPLATE = {
    'PayloadContent': [{
        'PayloadType': 'com.apple.dock',
        'PayloadDescription': 'Dock Payload',
        'PayloadDisplayName': 'Dock',
        'PayloadVersion': 1,
        'orientation': 'right'
    }],
    'PayloadType': 'Configuration',
    'PayloadDescription': 'Superbe profile imbattable!!!',
    'PayloadDisplayName': 'Test User Profile with Dock',
    'PayloadVersion': 1,
    'PayloadOrganization': 'Zentral',
    'PayloadScope': 'User',
}


def build_profile(
    payload_display_name=None,
    payload_description=None,
    payload_identifier=None,
    payload_uuid=None,
    channel=Channel.Device
):
    if payload_uuid is None:
        payload_uuid = str(uuid.uuid4()).upper()
    if payload_identifier is None:
        payload_identifier = f"io.zentral.test.{payload_uuid}"
    profile = copy.deepcopy(PROFILE_TEMPLATE)
    profile["PayloadIdentifier"] = payload_identifier
    profile["PayloadUUID"] = payload_uuid
    profile["PayloadDisplayName"] = payload_display_name or get_random_string(16)
    profile["PayloadDescription"] = payload_description or get_random_string(32)
    profile["PayloadScope"] = "System" if channel == Channel.Device else "User"
    payload = profile["PayloadContent"][0]
    payload["PayloadIdentifier"] = f"{payload_identifier}.0"
    payload["PayloadUUID"] = str(uuid.uuid4()).upper()
    return plistlib.dumps(profile)


class TestMDMArtifacts(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(32))
        push_certificate = PushCertificate.objects.create(
            name=get_random_string(64),
            topic=get_random_string(256),
            not_before=datetime(2000, 1, 1),
            not_after=datetime(2050, 1, 1),
            certificate=get_random_string(64).encode("utf-8"),
            private_key=get_random_string(64).encode("utf-8")
        )
        cls.blueprint1 = Blueprint.objects.create(name=get_random_string(32))

        # Enrolled devices / user
        cls.enrolled_device_no_blueprint = EnrolledDevice.objects.create(
            push_certificate=push_certificate,
            serial_number=get_random_string(64),
            platform="macOS",
            udid=get_random_string(36),
            token=get_random_string(32).encode("utf-8"),
            push_magic=get_random_string(73),
            unlock_token=get_random_string(32).encode("utf-8")
        )
        cls.enrolled_device = EnrolledDevice.objects.create(
            push_certificate=push_certificate,
            serial_number=get_random_string(64),
            platform="macOS",
            blueprint=cls.blueprint1,
            udid=get_random_string(36),
            token=get_random_string(32).encode("utf-8"),
            push_magic=get_random_string(73),
            unlock_token=get_random_string(32).encode("utf-8")
        )
        cls.enrolled_user = EnrolledUser.objects.create(
            enrolled_device=cls.enrolled_device,
            user_id=str(uuid.uuid4()).upper(),
            long_name=get_random_string(),
            short_name=get_random_string(),
            token=get_random_string().encode("utf-8"),
        )
        cls.enrolled_device_awaiting_configuration = EnrolledDevice.objects.create(
            push_certificate=push_certificate,
            serial_number=get_random_string(64),
            platform="macOS",
            blueprint=cls.blueprint1,
            awaiting_configuration=True,
            udid=get_random_string(36),
            token=get_random_string(32).encode("utf-8"),
            push_magic=get_random_string(73),
            unlock_token=get_random_string(32).encode("utf-8")
        )

    def _force_artifact(
        self,
        version_count=1,
        artifact_type=ArtifactType.Profile,
        channel=Channel.Device,
        platforms=None,
        install_before_setup_assistant=False,
        auto_update=True,
        priority=0
    ):
        if platforms is None:
            platforms = Platform.all_values()
        artifact = Artifact.objects.create(
            name=get_random_string(32),
            type=artifact_type.name,
            channel=channel.name,
            platforms=platforms
        )
        artifact_versions = []
        payload_identifier = "{}.{}.{}".format(get_random_string(2), get_random_string(4), str(uuid.uuid4()))
        payload_identifier = None
        for version in range(version_count, 0, -1):
            artifact_version = ArtifactVersion.objects.create(artifact=artifact, version=version)
            artifact_versions.append(artifact_version)
            if artifact_type == ArtifactType.Profile:
                if payload_identifier is None:
                    payload_identifier = "{}.{}.{}".format(get_random_string(2),
                                                           get_random_string(4),
                                                           str(uuid.uuid4()).upper())
                payload_uuid = str(uuid.uuid4()).upper()
                payload_display_name = get_random_string(16)
                payload_description = get_random_string(32)
                Profile.objects.create(
                    artifact_version=artifact_version,
                    source=build_profile(
                        payload_display_name=payload_display_name,
                        payload_description=payload_description,
                        payload_identifier=payload_identifier,
                        payload_uuid=payload_uuid,
                        channel=channel
                    ),
                    payload_identifier=payload_identifier,
                    payload_uuid=payload_uuid,
                    payload_display_name=payload_display_name,
                    payload_description=payload_description
                )
        return artifact, artifact_versions

    def _force_blueprint_artifact(
        self,
        version_count=1,
        artifact_type=ArtifactType.Profile,
        channel=Channel.Device,
        platforms=None,
        install_before_setup_assistant=False,
        auto_update=True,
        priority=0,
        blueprint=None
    ):
        artifact, artifact_versions = self._force_artifact(
            version_count,
            artifact_type,
            channel,
            platforms,
            install_before_setup_assistant,
            auto_update,
            priority
        )
        BlueprintArtifact.objects.create(
            blueprint=blueprint or self.blueprint1,
            artifact=artifact,
            install_before_setup_assistant=install_before_setup_assistant,
            auto_update=auto_update,
            priority=priority,
        )
        return artifact, artifact_versions

    def _force_target_artifact_version(self, target, artifact_version):
        kwargs = {"artifact_version__artifact": artifact_version.artifact,
                  "defaults": {"artifact_version": artifact_version}}
        if isinstance(target, EnrolledDevice):
            model = DeviceArtifact
            kwargs["enrolled_device"] = target
        else:
            model = UserArtifact
            kwargs["enrolled_user"] = target
        return model.objects.update_or_create(**kwargs)[0]

    # ArtifactVersion.objects.next_to_install

    def test_no_blueprint_nothing_to_install(self):
        self.assertEqual(ArtifactVersion.objects.next_to_install(self.enrolled_device_no_blueprint), None)

    def test_empty_blueprint_nothing_to_install(self):
        self.assertEqual(ArtifactVersion.objects.next_to_install(self.enrolled_device), None)

    def test_blueprint_install_one_device_profile(self):
        artifact, artifact_versions = self._force_blueprint_artifact(version_count=2)
        self.assertEqual(ArtifactVersion.objects.next_to_install(self.enrolled_device),
                         artifact_versions[0])
        self.assertEqual(ArtifactVersion.objects.next_to_install(self.enrolled_device, fetch_all=True),
                         artifact_versions[:1])
        self.assertEqual(ArtifactVersion.objects.next_to_install(self.enrolled_user), None)

    def test_blueprint_install_one_device_profile_with_previous_error_older_version(self):
        artifact, artifact_versions = self._force_blueprint_artifact(version_count=2)
        DeviceCommand.objects.create(enrolled_device=self.enrolled_device,
                                     uuid=uuid.uuid4(),
                                     name="InstallProfile",
                                     artifact_version=artifact_versions[1],
                                     artifact_operation=ArtifactOperation.Installation.name,
                                     status="Error")
        self.assertEqual(ArtifactVersion.objects.next_to_install(self.enrolled_device),
                         artifact_versions[0])

    def test_blueprint_no_install_one_device_profile_with_previous_error_same_version(self):
        artifact, artifact_versions = self._force_blueprint_artifact(version_count=2)
        DeviceCommand.objects.create(enrolled_device=self.enrolled_device,
                                     uuid=uuid.uuid4(),
                                     name="InstallProfile",
                                     artifact_version=artifact_versions[0],
                                     artifact_operation=ArtifactOperation.Installation.name,
                                     status="Error")
        self.assertIsNone(ArtifactVersion.objects.next_to_install(self.enrolled_device))

    def test_blueprint_install_device_profile_priority(self):
        self._force_blueprint_artifact()
        artifact, artifact_versions = self._force_blueprint_artifact(priority=100)
        self.assertEqual(ArtifactVersion.objects.next_to_install(self.enrolled_device),
                         artifact_versions[0])

    def test_blueprint_install_device_profile_awaiting_configuration_true(self):
        self._force_blueprint_artifact(priority=100)
        artifact, artifact_versions = self._force_blueprint_artifact(install_before_setup_assistant=True)
        self.assertEqual(ArtifactVersion.objects.next_to_install(self.enrolled_device_awaiting_configuration),
                         artifact_versions[0])

    def test_blueprint_install_device_profile_awaiting_configuration_false(self):
        artifact, artifact_versions = self._force_blueprint_artifact(priority=100)
        self._force_blueprint_artifact(install_before_setup_assistant=True)
        self.assertEqual(ArtifactVersion.objects.next_to_install(self.enrolled_device),
                         artifact_versions[0])

    def test_blueprint_install_one_user_profile(self):
        artifact, artifact_versions = self._force_blueprint_artifact(version_count=2, channel=Channel.User)
        self.assertEqual(ArtifactVersion.objects.next_to_install(self.enrolled_user),
                         artifact_versions[0])
        self.assertEqual(ArtifactVersion.objects.next_to_install(self.enrolled_user, fetch_all=True),
                         artifact_versions[:1])
        self.assertEqual(ArtifactVersion.objects.next_to_install(self.enrolled_device), None)

    def test_blueprint_install_one_user_profile_with_previous_error_older_version(self):
        artifact, artifact_versions = self._force_blueprint_artifact(version_count=2, channel=Channel.User)
        UserCommand.objects.create(enrolled_user=self.enrolled_user,
                                   uuid=uuid.uuid4(),
                                   name="InstallProfile",
                                   artifact_version=artifact_versions[1],
                                   artifact_operation=ArtifactOperation.Installation.name,
                                   status="Error")
        self.assertEqual(ArtifactVersion.objects.next_to_install(self.enrolled_user),
                         artifact_versions[0])

    def test_blueprint_no_install_one_user_profile_with_previous_error_same_version(self):
        artifact, artifact_versions = self._force_blueprint_artifact(version_count=2, channel=Channel.User)
        UserCommand.objects.create(enrolled_user=self.enrolled_user,
                                   uuid=uuid.uuid4(),
                                   name="InstallProfile",
                                   artifact_version=artifact_versions[0],
                                   artifact_operation=ArtifactOperation.Installation.name,
                                   status="Error")
        self.assertIsNone(ArtifactVersion.objects.next_to_install(self.enrolled_user))

    def test_blueprint_install_one_user_profile_already_present(self):
        artifact, artifact_versions = self._force_blueprint_artifact(version_count=2, channel=Channel.User)
        UserArtifact.objects.update_or_create(enrolled_user=self.enrolled_user,
                                              artifact_version__artifact=artifact,
                                              defaults={"artifact_version": artifact_versions[0]})
        self.assertEqual(ArtifactVersion.objects.next_to_install(self.enrolled_user), None)

    def test_blueprint_install_one_user_profile_already_present_obsolete(self):
        artifact, artifact_versions = self._force_blueprint_artifact(version_count=2, channel=Channel.User)
        UserArtifact.objects.update_or_create(enrolled_user=self.enrolled_user,
                                              artifact_version__artifact=artifact,
                                              defaults={"artifact_version": artifact_versions[1]})
        self.assertEqual(ArtifactVersion.objects.next_to_install(self.enrolled_user),
                         artifact_versions[0])

    def test_blueprint_install_one_user_profile_no_auto_update(self):
        artifact, artifact_versions = self._force_blueprint_artifact(version_count=2,
                                                                     channel=Channel.User,
                                                                     auto_update=False)
        self.assertEqual(ArtifactVersion.objects.next_to_install(self.enrolled_user),
                         artifact_versions[0])

    def test_blueprint_install_one_user_profile_already_present_no_auto_update(self):
        artifact, artifact_versions = self._force_blueprint_artifact(version_count=2,
                                                                     channel=Channel.User,
                                                                     auto_update=False)
        UserArtifact.objects.update_or_create(enrolled_user=self.enrolled_user,
                                              artifact_version__artifact=artifact,
                                              defaults={"artifact_version": artifact_versions[1]})
        self.assertEqual(ArtifactVersion.objects.next_to_install(self.enrolled_user), None)

    # ArtifactVersion.objects.next_to_remove

    def test_no_blueprint_nothing_to_remove(self):
        self.assertEqual(ArtifactVersion.objects.next_to_remove(self.enrolled_device_no_blueprint), None)

    def test_empty_blueprint_nothing_to_remove(self):
        self.assertEqual(ArtifactVersion.objects.next_to_remove(self.enrolled_device), None)

    def test_no_blueprint_remove_one_device_profile(self):
        artifact, artifact_versions = self._force_artifact(version_count=1)
        self._force_target_artifact_version(self.enrolled_device_no_blueprint, artifact_versions[0])
        self.assertEqual(ArtifactVersion.objects.next_to_remove(self.enrolled_device_no_blueprint),
                         artifact_versions[0])
        self.assertEqual(ArtifactVersion.objects.next_to_remove(self.enrolled_device_no_blueprint, fetch_all=True),
                         artifact_versions)

    def test_no_blueprint_no_remove_one_device_profile_with_previous_error_same_version(self):
        artifact, artifact_versions = self._force_artifact(version_count=1)
        self._force_target_artifact_version(self.enrolled_device_no_blueprint, artifact_versions[0])
        DeviceCommand.objects.create(enrolled_device=self.enrolled_device_no_blueprint,
                                     uuid=uuid.uuid4(),
                                     name="RemoveProfile",
                                     artifact_version=artifact_versions[0],
                                     artifact_operation=ArtifactOperation.Removal.name,
                                     status="Error")
        self.assertIsNone(ArtifactVersion.objects.next_to_remove(self.enrolled_device_no_blueprint))

    def test_empty_blueprint_remove_one_device_profile(self):
        artifact, artifact_versions = self._force_artifact(version_count=1)
        self._force_target_artifact_version(self.enrolled_device, artifact_versions[0])
        self.assertEqual(ArtifactVersion.objects.next_to_remove(self.enrolled_device),
                         artifact_versions[0])
        self.assertEqual(ArtifactVersion.objects.next_to_remove(self.enrolled_user), None)

    def test_blueprint_do_not_remove_one_device_profile_same_version(self):
        artifact, artifact_versions = self._force_blueprint_artifact(version_count=2)
        self._force_target_artifact_version(self.enrolled_device, artifact_versions[0])
        self.assertEqual(ArtifactVersion.objects.next_to_remove(self.enrolled_device), None)

    def test_blueprint_do_not_remove_one_device_profile_different_version(self):
        artifact, artifact_versions = self._force_blueprint_artifact(version_count=2)
        self._force_target_artifact_version(self.enrolled_device, artifact_versions[1])
        self.assertEqual(ArtifactVersion.objects.next_to_remove(self.enrolled_device), None)
