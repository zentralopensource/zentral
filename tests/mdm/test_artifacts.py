import copy
import json
import os.path
import plistlib
from unittest.mock import patch
import uuid
from datetime import date, datetime, timedelta
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MachineTag, MetaBusinessUnit, Tag
from zentral.contrib.mdm.artifacts import Target, update_blueprint_serialized_artifacts
from zentral.contrib.mdm.models import (Asset, Artifact, ArtifactVersion, ArtifactVersionTag,
                                        Blueprint, BlueprintArtifact,
                                        Channel, DeviceArtifact,
                                        EnrolledDevice, EnrolledUser, EnterpriseApp,
                                        Location, LocationAsset,
                                        Platform, Profile, PushCertificate,
                                        StoreApp, TargetArtifact,
                                        UserArtifact)


PROFILE_TEMPLATE = {
    'PayloadContent': [{
        'PayloadType': 'com.apple.dock',
        'PayloadDescription': 'Dock Payload',
        'PayloadDisplayName': 'Dock',
        'PayloadVersion': 1,
        'orientation': 'right'
    }],
    'PayloadType': 'Configuration',
    'PayloadVersion': 1,
    'PayloadOrganization': 'Zentral',
}


def build_profile(
    payload_display_name=None,
    payload_description=None,
    payload_identifier=None,
    payload_uuid=None,
    channel=Channel.DEVICE
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
    profile["PayloadScope"] = "System" if channel == Channel.DEVICE else "User"
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
            long_name=get_random_string(12),
            short_name=get_random_string(12),
            token=get_random_string(12).encode("utf-8"),
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
        artifact_type=Artifact.Type.PROFILE,
        channel=Channel.DEVICE,
        platforms=None,
        install_during_setup_assistant=False,
        auto_update=True,
        requires=None,
    ):
        if platforms is None:
            platforms = Platform.values
        artifact = Artifact.objects.create(
            name=get_random_string(32),
            type=artifact_type,
            channel=channel,
            platforms=platforms,
            install_during_setup_assistant=install_during_setup_assistant,
            auto_update=auto_update,
        )
        if requires:
            if not isinstance(requires, list):
                requires = [requires]
            artifact.requires.set(requires)
        artifact_versions = []
        for version in range(version_count, 0, -1):
            artifact_version = ArtifactVersion.objects.create(
                artifact=artifact,
                version=version,
                macos=True,
            )
            artifact_versions.append(artifact_version)
            if artifact_type == Artifact.Type.PROFILE:
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
            elif artifact_type == Artifact.Type.ENTERPRISE_APP:
                EnterpriseApp.objects.create(
                    artifact_version=artifact_version,
                    filename="{}.pkg".format(get_random_string(17)),
                    product_id="{}.{}.{}".format(get_random_string(2), get_random_string(4), get_random_string(8)),
                    product_version="17",
                    manifest={"items": [{"assets": [{}]}]}
                )
            elif artifact_type == Artifact.Type.STORE_APP:
                asset = Asset.objects.create(
                    adam_id="1234567890",
                    pricing_param="STDQ",
                    product_type=Asset.ProductType.APP,
                    device_assignable=True,
                    revocable=True,
                    supported_platforms=[Platform.MACOS]
                )
                location = Location(
                    server_token_hash=get_random_string(40, allowed_chars='abcdef0123456789'),
                    server_token=get_random_string(12),
                    server_token_expiration_date=date(2050, 1, 1),
                    organization_name=get_random_string(12),
                    country_code="DE",
                    library_uid=str(uuid.uuid4()),
                    name=get_random_string(12),
                    platform="enterprisestore",
                    website_url="https://business.apple.com",
                    mdm_info_id=uuid.uuid4(),
                )
                location.set_notification_auth_token()
                location.save()
                location_asset = LocationAsset.objects.create(
                    asset=asset,
                    location=location
                )
                StoreApp.objects.create(
                    artifact_version=artifact_version,
                    location_asset=location_asset
                )

        return artifact, artifact_versions

    def _force_blueprint_artifact(
        self,
        version_count=1,
        artifact_type=Artifact.Type.PROFILE,
        channel=Channel.DEVICE,
        platforms=None,
        install_during_setup_assistant=False,
        auto_update=True,
        blueprint=None,
        requires=None,
    ):
        artifact, artifact_versions = self._force_artifact(
            version_count,
            artifact_type,
            channel,
            platforms,
            install_during_setup_assistant,
            auto_update,
            requires=requires,
        )
        blueprint_artifact, _ = BlueprintArtifact.objects.get_or_create(
            blueprint=blueprint or self.blueprint1,
            artifact=artifact,
            defaults={"macos": True},
        )
        update_blueprint_serialized_artifacts(self.blueprint1)
        return blueprint_artifact, artifact, artifact_versions

    def _build_status_report(self, extra_configurations):
        status_report = json.load(
            open(os.path.join(os.path.dirname(__file__), "testdata/status_report.json"), "rb")
        )
        configurations = status_report["StatusItems"]["management"]["declarations"]["configurations"]
        configurations.pop()
        for artifact_version, valid, active in extra_configurations:
            configurations.append({
                "valid": valid,
                "active": active,
                "identifier": f"zentral.legacy-profile.{artifact_version.artifact.pk}",
                "server-token": str(artifact_version.pk),
            })
        return status_report

    # default platforms

    def test_artifact_default_platforms(self):
        artifact = Artifact.objects.create(
            name=get_random_string(12),
            type=Artifact.Type.PROFILE,
            channel=Channel.DEVICE
        )
        self.assertEqual(set(artifact.platforms), set(Platform.values))

    # next_to_install

    def test_no_blueprint_nothing_to_install(self):
        self.assertIsNone(Target(self.enrolled_device_no_blueprint).next_to_install())

    def test_empty_blueprint_nothing_to_install(self):
        self.assertIsNone(Target(self.enrolled_device).next_to_install())

    def test_blueprint_install_one_device_profile(self):
        _, artifact, artifact_versions = self._force_blueprint_artifact(version_count=2)
        dev_target = Target(self.enrolled_device)
        self.assertEqual(dev_target.next_to_install(),
                         artifact_versions[0])
        self.assertEqual(list(dev_target.all_to_install()),
                         artifact_versions[:1])
        usr_target = Target(self.enrolled_device, self.enrolled_user)
        self.assertIsNone(usr_target.next_to_install())

    def test_blueprint_install_one_device_profile_with_previous_error_older_version(self):
        _, artifact, artifact_versions = self._force_blueprint_artifact(version_count=2)
        target = Target(self.enrolled_device)
        target.update_target_artifact(artifact_versions[1], TargetArtifact.Status.FAILED)
        self.assertEqual(target.next_to_install(),
                         artifact_versions[0])

    def test_blueprint_no_install_one_device_profile_with_previous_error_same_version(self):
        _, artifact, artifact_versions = self._force_blueprint_artifact(version_count=2)
        target = Target(self.enrolled_device)
        target.update_target_artifact(artifact_versions[0], TargetArtifact.Status.FAILED)
        self.assertIsNone(target.next_to_install())

    def test_blueprint_install_device_profile_requires(self):
        required_artifact, (av,) = self._force_artifact()
        self._force_blueprint_artifact(requires=required_artifact)
        self.assertEqual(Target(self.enrolled_device).next_to_install(), av)

    def test_blueprint_install_device_profile_awaiting_configuration_false(self):
        _, _, artifact_versions = self._force_blueprint_artifact()
        _, _, artifact_versions_2 = self._force_blueprint_artifact(install_during_setup_assistant=True)
        self.assertEqual(set(Target(self.enrolled_device).all_to_install()),
                         {artifact_versions[0], artifact_versions_2[0]})

    def test_blueprint_install_device_profile_awaiting_configuration_true(self):
        self._force_blueprint_artifact()
        _, _, artifact_versions = self._force_blueprint_artifact(install_during_setup_assistant=True)
        self.assertEqual(set(Target(self.enrolled_device_awaiting_configuration).all_to_install()),
                         {artifact_versions[0]})

    def test_blueprint_install_one_user_profile(self):
        _, artifact, artifact_versions = self._force_blueprint_artifact(version_count=2, channel=Channel.USER)
        usr_target = Target(self.enrolled_device, self.enrolled_user)
        self.assertEqual(usr_target.next_to_install(),
                         artifact_versions[0])
        self.assertEqual(list(usr_target.all_to_install()),
                         artifact_versions[:1])
        self.assertIsNone(Target(self.enrolled_device).next_to_install())

    def test_blueprint_install_one_user_profile_with_previous_error_older_version(self):
        _, artifact, artifact_versions = self._force_blueprint_artifact(version_count=2, channel=Channel.USER)
        target = Target(self.enrolled_device, self.enrolled_user)
        target.update_target_artifact(artifact_versions[1], TargetArtifact.Status.FAILED)
        self.assertEqual(target.next_to_install(), artifact_versions[0])

    def test_blueprint_no_install_one_user_profile_with_previous_error_same_version(self):
        _, artifact, artifact_versions = self._force_blueprint_artifact(version_count=2, channel=Channel.USER)
        target = Target(self.enrolled_device, self.enrolled_user)
        target.update_target_artifact(artifact_versions[0], TargetArtifact.Status.FAILED)
        self.assertIsNone(target.next_to_install())

    def test_blueprint_one_user_profile_reinstall_major(self):
        _, artifact, (av2, av1) = self._force_blueprint_artifact(version_count=2, channel=Channel.USER)
        artifact.reinstall_on_os_update = Artifact.ReinstallOnOSUpdate.MAJOR
        artifact.save()
        update_blueprint_serialized_artifacts(self.blueprint1)
        self.enrolled_device.os_version = "12.0.0"
        target = Target(self.enrolled_device, self.enrolled_user)
        target.update_target_artifact(av2, TargetArtifact.Status.INSTALLED)
        ua_qs = UserArtifact.objects.filter(enrolled_user=self.enrolled_user)
        self.assertEqual(ua_qs.count(), 1)
        ua = ua_qs.first()
        self.assertEqual(ua.artifact_version, av2)
        self.assertEqual(ua.status, TargetArtifact.Status.INSTALLED)
        self.assertEqual(ua.os_version_at_install_time, "12.0.0")
        # next install none
        self.assertIsNone(target.next_to_install())
        # minor update none
        self.enrolled_device.os_version = "12.1.0"
        self.assertIsNone(Target(self.enrolled_device, self.enrolled_user).next_to_install())
        # major update ok
        self.enrolled_device.os_version = "13.0.0"
        self.assertEqual(Target(self.enrolled_device, self.enrolled_user).next_to_install(), av2)

    def test_blueprint_one_user_profile_reinstall_minor(self):
        _, artifact, (av2, av1) = self._force_blueprint_artifact(version_count=2, channel=Channel.USER)
        artifact.reinstall_on_os_update = Artifact.ReinstallOnOSUpdate.MINOR
        artifact.save()
        update_blueprint_serialized_artifacts(self.blueprint1)
        self.enrolled_device.os_version = "12.0.0"
        target = Target(self.enrolled_device, self.enrolled_user)
        target.update_target_artifact(av2, TargetArtifact.Status.INSTALLED)
        ua_qs = UserArtifact.objects.filter(enrolled_user=self.enrolled_user)
        self.assertEqual(ua_qs.count(), 1)
        ua = ua_qs.first()
        self.assertEqual(ua.artifact_version, av2)
        self.assertEqual(ua.status, TargetArtifact.Status.INSTALLED)
        self.assertEqual(ua.os_version_at_install_time, "12.0.0")
        # next install none
        self.assertIsNone(target.next_to_install())
        # patch update none
        self.enrolled_device.os_version = "12.0.1"
        self.assertIsNone(Target(self.enrolled_device, self.enrolled_user).next_to_install())
        # minor update ok
        self.enrolled_device.os_version = "12.1.0"
        self.assertEqual(Target(self.enrolled_device, self.enrolled_user).next_to_install(), av2)

    def test_blueprint_one_user_profile_reinstall_patch(self):
        _, artifact, (av2, av1) = self._force_blueprint_artifact(version_count=2, channel=Channel.USER)
        artifact.reinstall_on_os_update = Artifact.ReinstallOnOSUpdate.PATCH
        artifact.save()
        update_blueprint_serialized_artifacts(self.blueprint1)
        self.enrolled_device.os_version = "12.0.0"
        target = Target(self.enrolled_device, self.enrolled_user)
        target.update_target_artifact(av2, TargetArtifact.Status.INSTALLED)
        ua_qs = UserArtifact.objects.filter(enrolled_user=self.enrolled_user)
        self.assertEqual(ua_qs.count(), 1)
        ua = ua_qs.first()
        self.assertEqual(ua.artifact_version, av2)
        self.assertEqual(ua.status, TargetArtifact.Status.INSTALLED)
        self.assertEqual(ua.os_version_at_install_time, "12.0.0")
        # next install none
        self.assertIsNone(target.next_to_install())
        # patch update ok
        self.enrolled_device.os_version = "12.0.1"
        self.assertEqual(Target(self.enrolled_device, self.enrolled_user).next_to_install(), av2)

    def test_blueprint_one_device_profile_reinstall_interval_noop(self):
        _, artifact, (av2, av1) = self._force_blueprint_artifact(version_count=2)
        artifact.reinstall_interval = 90  # in days
        artifact.save()
        update_blueprint_serialized_artifacts(self.blueprint1)
        # update target artifact
        target = Target(self.enrolled_device)
        target.update_target_artifact(av2, TargetArtifact.Status.INSTALLED)
        da_qs = DeviceArtifact.objects.filter(enrolled_device=self.enrolled_device)
        self.assertEqual(da_qs.count(), 1)
        da = da_qs.first()
        self.assertEqual(da.artifact_version, av2)
        self.assertEqual(da.status, TargetArtifact.Status.INSTALLED)
        # sanity check
        self.assertTrue(datetime.utcnow() < da.installed_at + timedelta(days=artifact.reinstall_interval))
        # since above is True, no reinstall
        self.assertIsNone(target.next_to_install())

    def test_blueprint_one_device_profile_reinstall_interval(self):
        _, artifact, (av2, av1) = self._force_blueprint_artifact(version_count=2)
        artifact.reinstall_interval = 90  # in days
        artifact.save()
        update_blueprint_serialized_artifacts(self.blueprint1)
        # update target artifact
        target = Target(self.enrolled_device)
        target.update_target_artifact(av2, TargetArtifact.Status.INSTALLED)
        da_qs = DeviceArtifact.objects.filter(enrolled_device=self.enrolled_device)
        self.assertEqual(da_qs.count(), 1)
        da = da_qs.first()
        self.assertEqual(da.artifact_version, av2)
        self.assertEqual(da.status, TargetArtifact.Status.INSTALLED)
        da.installed_at = datetime.utcnow() - timedelta(days=artifact.reinstall_interval) - timedelta(days=1)
        da.save()
        # sanity check
        self.assertFalse(datetime.utcnow() < da.installed_at + timedelta(days=artifact.reinstall_interval))
        # since above is False, reinstall
        self.assertEqual(target.next_to_install(), av2)

    def test_blueprint_install_one_user_profile_already_present(self):
        _, artifact, artifact_versions = self._force_blueprint_artifact(version_count=2, channel=Channel.USER)
        target = Target(self.enrolled_device, self.enrolled_user)
        target.update_target_artifact(artifact_versions[0], TargetArtifact.Status.INSTALLED)
        self.assertIsNone(target.next_to_install())

    def test_blueprint_install_one_user_profile_already_present_obsolete(self):
        _, artifact, artifact_versions = self._force_blueprint_artifact(version_count=2, channel=Channel.USER)
        target = Target(self.enrolled_device, self.enrolled_user)
        target.update_target_artifact(artifact_versions[1], TargetArtifact.Status.INSTALLED)
        self.assertEqual(target.next_to_install(), artifact_versions[0])

    def test_blueprint_no_install_one_user_profile_awaiting_confirmation(self):
        _, artifact, artifact_versions = self._force_blueprint_artifact(version_count=2, channel=Channel.USER)
        # old version installed
        UserArtifact.objects.update_or_create(enrolled_user=self.enrolled_user,
                                              artifact_version=artifact_versions[1],
                                              status=TargetArtifact.Status.INSTALLED)
        # new version awaiting confirmation
        UserArtifact.objects.update_or_create(enrolled_user=self.enrolled_user,
                                              artifact_version=artifact_versions[0],
                                              status=TargetArtifact.Status.AWAITING_CONFIRMATION)
        self.assertIsNone(Target(self.enrolled_device, self.enrolled_user).next_to_install())

    def test_blueprint_install_one_user_profile_no_auto_update(self):
        _, artifact, artifact_versions = self._force_blueprint_artifact(version_count=2,
                                                                        channel=Channel.USER,
                                                                        auto_update=False)
        self.assertEqual(Target(self.enrolled_device, self.enrolled_user).next_to_install(),
                         artifact_versions[0])

    def test_blueprint_install_one_user_profile_already_present_no_auto_update(self):
        _, artifact, artifact_versions = self._force_blueprint_artifact(version_count=2,
                                                                        channel=Channel.USER,
                                                                        auto_update=False)
        target = Target(self.enrolled_device, self.enrolled_user)
        target.update_target_artifact(artifact_versions[1], TargetArtifact.Status.INSTALLED)
        self.assertIsNone(target.next_to_install())

    def test_blueprint_install_one_device_profile_other_min_max_os_version(self):
        _, artifact, (av2, av1) = self._force_blueprint_artifact(version_count=2)
        self.assertEqual(av1.version, 1)
        self.assertEqual(av2.version, 2)
        # higher version by default
        self.assertEqual(Target(self.enrolled_device).next_to_install(), av2)
        # higher version not available
        # new target to avoid cache
        target = Target(self.enrolled_device)
        self.assertEqual(target.comparable_os_version, (0, 0, 0))
        av1.macos_max_version = "13.1.0"  # not included
        av1.save()
        av2.macos_min_version = "13.1.0"  # included
        av2.save()
        update_blueprint_serialized_artifacts(self.blueprint1)
        self.assertEqual(target.next_to_install(), av1)
        # higher version available
        # new target to avoid cache
        self.enrolled_device.os_version = "13.1.0"
        target = Target(self.enrolled_device)
        self.assertEqual(target.comparable_os_version, (13, 1, 0))
        self.assertEqual(target.next_to_install(), av2)

    def test_blueprint_install_one_device_profile_other_min_max_os_version_no_candidate(self):
        _, artifact, (av2, av1) = self._force_blueprint_artifact(version_count=2)
        self.assertEqual(av1.version, 1)
        self.assertEqual(av2.version, 2)
        # bad configuration, because min/max versions with gap
        av1.macos_max_version = "13.1.0"  # not included
        av1.save()
        av2.macos_min_version = "13.1.1"  # included
        av2.save()
        update_blueprint_serialized_artifacts(self.blueprint1)
        self.enrolled_device.os_version = "13.1.0"
        target = Target(self.enrolled_device)
        self.assertEqual(target.comparable_os_version, (13, 1, 0))
        self.assertIsNone(target.next_to_install())

    def test_blueprint_profile_wrong_platform(self):
        bp_artifact, artifact, (av,) = self._force_blueprint_artifact()
        self.assertEqual(Target(self.enrolled_device).next_to_install(), av)
        self.enrolled_device.platform = Platform.IOS
        self.assertIsNone(Target(self.enrolled_device).next_to_install())

    def test_blueprint_profile_excluded_tag(self):
        bp_artifact, artifact, (av,) = self._force_blueprint_artifact()
        self.assertEqual(Target(self.enrolled_device).next_to_install(), av)
        tag = Tag.objects.create(name=get_random_string(12))
        bp_artifact.excluded_tags.add(tag)
        update_blueprint_serialized_artifacts(self.blueprint1)
        MachineTag.objects.create(serial_number=self.enrolled_device.serial_number, tag=tag)
        self.assertIsNone(Target(self.enrolled_device).next_to_install())

    @patch("zentral.contrib.mdm.artifacts.compute_shard")
    def test_blueprint_profile_default_shard_not_ok(self, compute_shard):
        bp_artifact, _, (av,) = self._force_blueprint_artifact()
        self.assertEqual(Target(self.enrolled_device).next_to_install(), av)
        bp_artifact.default_shard = 10
        compute_shard.return_value = 15  # too high
        bp_artifact.save()
        update_blueprint_serialized_artifacts(self.blueprint1)
        self.assertIsNone(Target(self.enrolled_device).next_to_install())

    @patch("zentral.contrib.mdm.artifacts.compute_shard")
    def test_blueprint_profile_default_shard_ok(self, compute_shard):
        bp_artifact, _, (av,) = self._force_blueprint_artifact()
        self.assertEqual(Target(self.enrolled_device).next_to_install(), av)
        bp_artifact.default_shard = 10
        compute_shard.return_value = 5  # ok
        bp_artifact.save()
        update_blueprint_serialized_artifacts(self.blueprint1)
        self.assertEqual(Target(self.enrolled_device).next_to_install(), av)

    @patch("zentral.contrib.mdm.artifacts.compute_shard")
    def test_blueprint_profile_av_tag_shard_ok(self, compute_shard):
        _, _, (av2, av1) = self._force_blueprint_artifact(version_count=2)
        self.assertEqual(av1.version, 1)
        self.assertEqual(av2.version, 2)
        # higher version by default
        self.assertEqual(Target(self.enrolled_device).next_to_install(), av2)
        # machine with both tags
        tag1 = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number=self.enrolled_device.serial_number, tag=tag1)
        tag2 = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number=self.enrolled_device.serial_number, tag=tag2)
        av2.default_shard = 0
        av2.save()
        ArtifactVersionTag.objects.create(artifact_version=av2, tag=tag2, shard=10)
        update_blueprint_serialized_artifacts(self.blueprint1)
        compute_shard.return_value = 5  # ok
        self.assertEqual(Target(self.enrolled_device).next_to_install(), av2)

    @patch("zentral.contrib.mdm.artifacts.compute_shard")
    def test_blueprint_profile_av_tag_shard_not_ok(self, compute_shard):
        _, _, (av2, av1) = self._force_blueprint_artifact(version_count=2)
        self.assertEqual(av1.version, 1)
        self.assertEqual(av2.version, 2)
        # higher version by default
        self.assertEqual(Target(self.enrolled_device).next_to_install(), av2)
        # machine with both tags
        tag1 = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number=self.enrolled_device.serial_number, tag=tag1)
        tag2 = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number=self.enrolled_device.serial_number, tag=tag2)
        av2.default_shard = 0
        av2.save()
        ArtifactVersionTag.objects.create(artifact_version=av2, tag=tag2, shard=10)
        update_blueprint_serialized_artifacts(self.blueprint1)
        compute_shard.return_value = 15  # too high
        self.assertEqual(Target(self.enrolled_device).next_to_install(), av1)

    def test_blueprint_install_one_enterprise_app_exclude_profile(self):
        _, _, profile_avs = self._force_blueprint_artifact(
            artifact_type=Artifact.Type.PROFILE,
            version_count=1
        )
        _, _, enterprise_app_avs = self._force_blueprint_artifact(
            artifact_type=Artifact.Type.ENTERPRISE_APP,
            version_count=1,
        )
        # no included_types, all
        target = Target(self.enrolled_device)
        self.assertEqual(
            set(target.all_to_install()),
            {profile_avs[0], enterprise_app_avs[0]}
        )
        # included_types set, profile not included → enterprise app
        self.assertEqual(
            set(target.all_to_install(included_types=(Artifact.Type.ENTERPRISE_APP, Artifact.Type.STORE_APP))),
            {enterprise_app_avs[0]}
        )

    def test_blueprint_install_one_enterprise_app_exclude_profile_dependency(self):
        _, profile_a, (profile_av,) = self._force_blueprint_artifact(
            artifact_type=Artifact.Type.PROFILE,
            version_count=1
        )
        _, _, enterprise_app_avs = self._force_blueprint_artifact(
            artifact_type=Artifact.Type.ENTERPRISE_APP,
            version_count=1,
            requires=profile_a,
        )
        # no included_types, start with the profile
        target = Target(self.enrolled_device)
        self.assertEqual(target.next_to_install(), profile_av)
        # included_types set, profile not included → no progress possible
        self.assertIsNone(target.next_to_install(included_types=(Artifact.Type.ENTERPRISE_APP,
                                                                 Artifact.Type.STORE_APP)))

    # next_to_remove

    def test_no_blueprint_nothing_to_remove(self):
        self.assertIsNone(Target(self.enrolled_device_no_blueprint).next_to_remove())

    def test_empty_blueprint_nothing_to_remove(self):
        self.assertIsNone(Target(self.enrolled_device).next_to_remove())

    def test_no_blueprint_remove_one_device_profile(self):
        artifact, artifact_versions = self._force_artifact(version_count=1)
        target = Target(self.enrolled_device_no_blueprint)
        target.update_target_artifact(
            artifact_versions[0],
            TargetArtifact.Status.INSTALLED
        )
        self.assertEqual(target.next_to_remove(), artifact_versions[0])

    def test_no_blueprint_no_remove_one_device_profile_with_previous_error_same_version(self):
        artifact, artifact_versions = self._force_artifact(version_count=1)
        target = Target(self.enrolled_device_no_blueprint)
        target.update_target_artifact(
            artifact_versions[0],
            TargetArtifact.Status.REMOVAL_FAILED,
        )
        self.assertIsNone(target.next_to_remove())

    def test_empty_blueprint_remove_one_device_profile(self):
        artifact, artifact_versions = self._force_artifact(version_count=1)
        dev_target = Target(self.enrolled_device)
        dev_target.update_target_artifact(
            artifact_versions[0],
            TargetArtifact.Status.INSTALLED
        )
        self.assertEqual(dev_target.next_to_remove(), artifact_versions[0])
        usr_target = Target(self.enrolled_device, self.enrolled_user)
        self.assertIsNone(usr_target.next_to_remove())

    def test_empty_blueprint_no_remove_one_enterprise_application(self):
        artifact, artifact_versions = self._force_artifact(version_count=1,
                                                           artifact_type=Artifact.Type.ENTERPRISE_APP)
        target = Target(self.enrolled_device)
        target.update_target_artifact(
            artifact_versions[0],
            TargetArtifact.Status.INSTALLED
        )
        # cannot remove Enterprise Apps
        self.assertIsNone(target.next_to_remove())

    def test_blueprint_do_not_remove_one_device_profile_same_version(self):
        _, artifact, artifact_versions = self._force_blueprint_artifact(version_count=2)
        target = Target(self.enrolled_device)
        target.update_target_artifact(
            artifact_versions[0],
            TargetArtifact.Status.INSTALLED
        )
        self.assertIsNone(target.next_to_remove())

    def test_blueprint_do_not_remove_one_enterprise_app_same_version(self):
        _, artifact, artifact_versions = self._force_blueprint_artifact(version_count=2,
                                                                        artifact_type=Artifact.Type.ENTERPRISE_APP)
        target = Target(self.enrolled_device)
        target.update_target_artifact(artifact_versions[0], TargetArtifact.Status.INSTALLED)
        self.assertIsNone(target.next_to_remove())

    def test_blueprint_do_not_remove_one_device_profile_different_version(self):
        _, artifact, artifact_versions = self._force_blueprint_artifact(version_count=2)
        target = Target(self.enrolled_device)
        target.update_target_artifact(artifact_versions[1], TargetArtifact.Status.INSTALLED)
        self.assertIsNone(target.next_to_remove())

    def test_empty_blueprint_remove_one_store_app_exclude_profile(self):
        _, (profile_av,) = self._force_artifact(
            artifact_type=Artifact.Type.PROFILE,
            version_count=1
        )
        _, (store_app_av,) = self._force_artifact(
            artifact_type=Artifact.Type.STORE_APP,
            version_count=1,
        )
        target = Target(self.enrolled_device)
        target.update_target_artifact(profile_av, TargetArtifact.Status.INSTALLED)
        target.update_target_artifact(store_app_av, TargetArtifact.Status.INSTALLED)
        # no included_types, one of the two
        self.assertIn(target.next_to_remove(), (profile_av, store_app_av))
        # included_types set, profile not included → store app
        self.assertEqual(
            target.next_to_remove(included_types=(Artifact.Type.STORE_APP,)),
            store_app_av
        )

    # activation

    def test_device_activation_store_app_not_included(self):
        _, profile_a, (profile_av,) = self._force_blueprint_artifact()
        activation = Target(self.enrolled_device).activation
        self.assertEqual(sorted(activation.keys()), ["Identifier", "Payload", "ServerToken", "Type"])
        self.assertEqual(sorted(activation["Payload"].keys()), ["StandardConfigurations"])
        scs = activation["Payload"]["StandardConfigurations"]
        self.assertEqual(len(scs), 2)
        self.assertIn(f"zentral.blueprint.{self.blueprint1.pk}.management-status-subscriptions", scs)
        self.assertIn(f"zentral.legacy-profile.{profile_a.pk}", scs)

    def test_user_declaration_items_store_app_not_included(self):
        _, profile_a, (profile_av,) = self._force_blueprint_artifact(channel=Channel.USER)
        profile_a.reinstall_on_os_update = Artifact.ReinstallOnOSUpdate.PATCH
        profile_a.reinstall_interval = 100000
        profile_a.save()
        self._force_blueprint_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP, channel=Channel.USER)
        self.enrolled_device.os_version = "13.1.0"
        target = Target(self.enrolled_device, self.enrolled_user)
        declaration_items = target.declaration_items
        self.assertEqual(sorted(declaration_items.keys()), ["Declarations", "DeclarationsToken"])
        declarations = declaration_items["Declarations"]
        self.assertEqual(sorted(declarations.keys()), ["Activations", "Assets", "Configurations", "Management"])
        self.assertEqual(len(declarations["Assets"]), 0)
        self.assertEqual(len(declarations["Management"]), 0)
        self.assertEqual(
            declarations["Activations"],
            [{"Identifier": target.activation["Identifier"],
              "ServerToken": target.activation["ServerToken"]}],
        )
        configurations = declarations["Configurations"]
        self.assertEqual(len(configurations), 2)
        self.assertEqual(configurations[0]["Identifier"],
                         f"zentral.blueprint.{self.blueprint1.pk}.management-status-subscriptions")
        self.assertEqual(configurations[0]["ServerToken"], "0ed215547af3061ce18ea6cf7a69dac4a3d52f3f")
        self.assertEqual(configurations[1]["Identifier"], f"zentral.legacy-profile.{profile_a.pk}")
        self.assertEqual(configurations[1]["ServerToken"], f"{profile_av.pk}.ov-13.1.0.ri-0")

    # update_target_artifact

    @patch("zentral.contrib.mdm.artifacts.datetime")
    def test_update_target_artifact_no_reinstall(self, patched_datetime):
        patched_datetime.utcnow.side_effect = (
            datetime(2001, 2, 3, 4, 5, 6),
            datetime(2002, 3, 4, 5, 6, 7),
        )
        _, profile_a, (profile_av,) = self._force_blueprint_artifact()
        target = Target(self.enrolled_device)
        target.update_target_artifact(profile_av, TargetArtifact.Status.INSTALLED)
        da_qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=profile_a,
        )
        self.assertEqual(da_qs.count(), 1)
        da = da_qs.first()
        self.assertEqual(da.artifact_version, profile_av)
        self.assertEqual(da.status, TargetArtifact.Status.INSTALLED)
        self.assertEqual(da.installed_at, datetime(2001, 2, 3, 4, 5, 6))
        self.assertIsNone(da.os_version_at_install_time)
        target.update_target_artifact(profile_av, TargetArtifact.Status.INSTALLED)
        self.assertEqual(da_qs.count(), 1)
        da.refresh_from_db()
        # no reinstall
        self.assertEqual(da.installed_at, datetime(2001, 2, 3, 4, 5, 6))

    @patch("zentral.contrib.mdm.artifacts.datetime")
    def test_update_target_artifact_allow_reinstall(self, patched_datetime):
        patched_datetime.utcnow.side_effect = (
            datetime(2001, 2, 3, 4, 5, 6),
            datetime(2002, 3, 4, 5, 6, 7),
        )
        _, profile_a, (profile_av,) = self._force_blueprint_artifact()
        target = Target(self.enrolled_device)
        target.update_target_artifact(profile_av, TargetArtifact.Status.INSTALLED)
        da_qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=profile_a,
        )
        self.assertEqual(da_qs.count(), 1)
        da = da_qs.first()
        self.assertEqual(da.artifact_version, profile_av)
        self.assertEqual(da.status, TargetArtifact.Status.INSTALLED)
        self.assertEqual(da.installed_at, datetime(2001, 2, 3, 4, 5, 6))
        self.assertIsNone(da.os_version_at_install_time)
        target.update_target_artifact(profile_av, TargetArtifact.Status.INSTALLED, allow_reinstall=True)
        self.assertEqual(da_qs.count(), 1)
        da.refresh_from_db()
        # reinstall
        self.assertEqual(da.installed_at, datetime(2002, 3, 4, 5, 6, 7))

    @patch("zentral.contrib.mdm.artifacts.datetime")
    def test_update_target_artifact_same_uii_no_reinstall(self, patched_datetime):
        patched_datetime.utcnow.side_effect = (
            datetime(2001, 2, 3, 4, 5, 6),
            datetime(2002, 3, 4, 5, 6, 7),
        )
        _, profile_a, (profile_av,) = self._force_blueprint_artifact()
        target = Target(self.enrolled_device)
        target.update_target_artifact(
            profile_av,
            TargetArtifact.Status.INSTALLED,
            unique_install_identifier=str(profile_av.pk)
        )
        da_qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=profile_a,
        )
        self.assertEqual(da_qs.count(), 1)
        da = da_qs.first()
        self.assertEqual(da.artifact_version, profile_av)
        self.assertEqual(da.status, TargetArtifact.Status.INSTALLED)
        self.assertEqual(da.installed_at, datetime(2001, 2, 3, 4, 5, 6))
        self.assertIsNone(da.os_version_at_install_time)
        target.update_target_artifact(
            profile_av,
            TargetArtifact.Status.INSTALLED,
            unique_install_identifier=str(profile_av.pk)
        )
        self.assertEqual(da_qs.count(), 1)
        da.refresh_from_db()
        # no reinstall
        self.assertEqual(da.installed_at, datetime(2001, 2, 3, 4, 5, 6))

    @patch("zentral.contrib.mdm.artifacts.datetime")
    def test_update_target_artifact_uii_diff_reinstall(self, patched_datetime):
        patched_datetime.utcnow.side_effect = (
            datetime(2001, 2, 3, 4, 5, 6),
            datetime(2002, 3, 4, 5, 6, 7),
        )
        _, profile_a, (profile_av,) = self._force_blueprint_artifact()
        self.enrolled_device.os_version = "13.3.1"
        target = Target(self.enrolled_device)
        target.update_target_artifact(
            profile_av,
            TargetArtifact.Status.INSTALLED,
            unique_install_identifier=str(profile_av.pk)
        )
        da_qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=profile_a,
        )
        self.assertEqual(da_qs.count(), 1)
        da = da_qs.first()
        self.assertEqual(da.artifact_version, profile_av)
        self.assertEqual(da.status, TargetArtifact.Status.INSTALLED)
        self.assertEqual(da.installed_at, datetime(2001, 2, 3, 4, 5, 6))
        self.assertEqual(da.os_version_at_install_time, "13.3.1")
        self.assertEqual(da.unique_install_identifier, str(profile_av.pk))
        self.enrolled_device.os_version = "13.4.0"
        target = Target(self.enrolled_device)
        target.update_target_artifact(
            profile_av,
            TargetArtifact.Status.INSTALLED,
            unique_install_identifier=str(profile_av.pk) + "diff"
        )
        self.assertEqual(da_qs.count(), 1)
        da.refresh_from_db()
        # reinstall
        self.assertEqual(da.artifact_version, profile_av)
        self.assertEqual(da.status, TargetArtifact.Status.INSTALLED)
        self.assertEqual(da.installed_at, datetime(2002, 3, 4, 5, 6, 7))
        self.assertEqual(da.os_version_at_install_time, "13.4.0")
        self.assertEqual(da.unique_install_identifier, str(profile_av.pk) + "diff")

    @patch("zentral.contrib.mdm.artifacts.datetime")
    def test_update_target_artifact_failed_reinstall_reset(self, patched_datetime):
        patched_datetime.utcnow.side_effect = (
            datetime(2001, 2, 3, 4, 5, 6),
            datetime(2002, 3, 4, 5, 6, 7),
        )
        _, profile_a, (profile_av,) = self._force_blueprint_artifact()
        self.enrolled_device.os_version = "13.3.1"
        target = Target(self.enrolled_device)
        target.update_target_artifact(
            profile_av,
            TargetArtifact.Status.INSTALLED,
            unique_install_identifier=str(profile_av.pk)
        )
        da_qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=profile_a,
        )
        self.assertEqual(da_qs.count(), 1)
        da = da_qs.first()
        self.assertEqual(da.artifact_version, profile_av)
        self.assertEqual(da.status, TargetArtifact.Status.INSTALLED)
        self.assertEqual(da.installed_at, datetime(2001, 2, 3, 4, 5, 6))
        self.assertEqual(da.os_version_at_install_time, "13.3.1")
        self.enrolled_device.os_version = "13.4.0"
        target = Target(self.enrolled_device)  # avoid os version cache
        target.update_target_artifact(
            profile_av,
            TargetArtifact.Status.FAILED,
            unique_install_identifier=str(profile_av.pk) + "diff"
        )
        self.assertEqual(da_qs.count(), 1)
        da.refresh_from_db()
        # reinstall
        self.assertEqual(da.status, TargetArtifact.Status.FAILED)
        self.assertIsNone(da.installed_at)
        self.assertIsNone(da.os_version_at_install_time)
        self.assertEqual(da.unique_install_identifier, "")

    @patch("zentral.contrib.mdm.artifacts.datetime")
    def test_update_target_artifact_install_over_failed_update(self, patched_datetime):
        patched_datetime.utcnow.side_effect = (
            datetime(2001, 2, 3, 4, 5, 6),
            datetime(2002, 3, 4, 5, 6, 7),
        )
        _, profile_a, (profile_av,) = self._force_blueprint_artifact()
        self.enrolled_device.os_version = "13.3.1"
        target = Target(self.enrolled_device)
        target.update_target_artifact(
            profile_av,
            TargetArtifact.Status.FAILED,
            unique_install_identifier=str(profile_av.pk)
        )
        da_qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=profile_a,
        )
        self.assertEqual(da_qs.count(), 1)
        da = da_qs.first()
        self.assertEqual(da.artifact_version, profile_av)
        self.assertEqual(da.status, TargetArtifact.Status.FAILED)
        self.assertIsNone(da.installed_at)
        self.assertIsNone(da.os_version_at_install_time)
        self.assertEqual(da.unique_install_identifier, "")
        self.enrolled_device.os_version = "13.4.0"
        target = Target(self.enrolled_device)  # avoid os version cache
        target.update_target_artifact(
            profile_av,
            TargetArtifact.Status.INSTALLED,
            unique_install_identifier=str(profile_av.pk)
        )
        self.assertEqual(da_qs.count(), 1)
        da.refresh_from_db()
        # update
        self.assertEqual(da.status, TargetArtifact.Status.INSTALLED)
        self.assertEqual(da.installed_at, datetime(2001, 2, 3, 4, 5, 6))
        self.assertEqual(da.os_version_at_install_time, "13.4.0")
        self.assertEqual(da.unique_install_identifier, str(profile_av.pk))

    @patch("zentral.contrib.mdm.artifacts.datetime")
    def test_update_target_artifact_upgrade_update(self, patched_datetime):
        patched_datetime.utcnow.side_effect = (
            datetime(2001, 2, 3, 4, 5, 6),
            datetime(2002, 3, 4, 5, 6, 7),
        )
        _, profile_a, (profile_av2, profile_av1) = self._force_blueprint_artifact(version_count=2)
        self.enrolled_device.os_version = "13.3.1"
        target = Target(self.enrolled_device)
        target.update_target_artifact(
            profile_av1,
            TargetArtifact.Status.INSTALLED,
        )
        da_qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=profile_a,
        )
        self.assertEqual(da_qs.count(), 1)
        da = da_qs.first()
        self.assertEqual(da.artifact_version, profile_av1)
        self.assertEqual(da.status, TargetArtifact.Status.INSTALLED)
        self.assertEqual(da.installed_at, datetime(2001, 2, 3, 4, 5, 6))
        self.assertEqual(da.os_version_at_install_time, "13.3.1")
        self.assertEqual(da.unique_install_identifier, "")
        self.enrolled_device.os_version = "13.4.0"
        target = Target(self.enrolled_device)  # avoid os version cache
        target.update_target_artifact(
            profile_av2,
            TargetArtifact.Status.INSTALLED,
        )
        self.assertEqual(da_qs.count(), 1)
        # update + cleanup
        da2 = da_qs.first()
        self.assertEqual(da2.artifact_version, profile_av2)
        self.assertEqual(da2.status, TargetArtifact.Status.INSTALLED)
        self.assertEqual(da2.installed_at, datetime(2002, 3, 4, 5, 6, 7))
        self.assertEqual(da2.os_version_at_install_time, "13.4.0")
        self.assertEqual(da2.unique_install_identifier, "")

    @patch("zentral.contrib.mdm.artifacts.datetime")
    def test_update_target_artifact_upgrade_over_failed_install(self, patched_datetime):
        patched_datetime.utcnow.side_effect = (
            datetime(2001, 2, 3, 4, 5, 6),
            datetime(2002, 3, 4, 5, 6, 7),
        )
        _, profile_a, (profile_av2, profile_av1) = self._force_blueprint_artifact(version_count=2)
        self.enrolled_device.os_version = "13.3.1"
        target = Target(self.enrolled_device)
        target.update_target_artifact(
            profile_av1,
            TargetArtifact.Status.FAILED,
            unique_install_identifier=str(profile_av1.pk)
        )
        da_qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=profile_a,
        )
        self.assertEqual(da_qs.count(), 1)
        da = da_qs.first()
        self.assertEqual(da.artifact_version, profile_av1)
        self.assertEqual(da.status, TargetArtifact.Status.FAILED)
        self.assertIsNone(da.installed_at)
        self.assertIsNone(da.os_version_at_install_time)
        self.assertEqual(da.unique_install_identifier, "")
        self.enrolled_device.os_version = "13.4.0"
        target = Target(self.enrolled_device)  # avoid os version cache
        target.update_target_artifact(
            profile_av2,
            TargetArtifact.Status.INSTALLED,
            unique_install_identifier=str(profile_av2.pk)
        )
        self.assertEqual(da_qs.count(), 1)
        da2 = da_qs.first()
        self.assertNotEqual(da2, da)
        self.assertEqual(da2.artifact_version, profile_av2)
        self.assertEqual(da2.status, TargetArtifact.Status.INSTALLED)
        self.assertEqual(da2.installed_at, datetime(2001, 2, 3, 4, 5, 6))
        self.assertEqual(da2.os_version_at_install_time, "13.4.0")
        self.assertEqual(da2.unique_install_identifier, str(profile_av2.pk))

    @patch("zentral.contrib.mdm.artifacts.datetime")
    def test_update_target_artifact_failed_upgrade_over_failed_install(self, patched_datetime):
        patched_datetime.utcnow.side_effect = (
            datetime(2001, 2, 3, 4, 5, 6),
            datetime(2002, 3, 4, 5, 6, 7),
        )
        _, profile_a, (profile_av2, profile_av1) = self._force_blueprint_artifact(version_count=2)
        self.enrolled_device.os_version = "13.3.1"
        target = Target(self.enrolled_device)
        target.update_target_artifact(
            profile_av1,
            TargetArtifact.Status.FAILED,
            unique_install_identifier=str(profile_av1.pk)
        )
        da_qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=profile_a,
        ).order_by("created_at")
        self.assertEqual(da_qs.count(), 1)
        da = da_qs.first()
        self.assertEqual(da.artifact_version, profile_av1)
        self.assertEqual(da.status, TargetArtifact.Status.FAILED)
        self.assertIsNone(da.installed_at)
        self.assertIsNone(da.os_version_at_install_time)
        self.assertEqual(da.unique_install_identifier, "")
        self.enrolled_device.os_version = "13.4.0"
        target = Target(self.enrolled_device)  # avoid os version cache
        target.update_target_artifact(
            profile_av2,
            TargetArtifact.Status.FAILED,
            unique_install_identifier=str(profile_av2.pk)
        )
        self.assertEqual(da_qs.count(), 2)
        # first da untouched
        da.refresh_from_db()
        self.assertEqual(da.artifact_version, profile_av1)
        self.assertEqual(da.status, TargetArtifact.Status.FAILED)
        self.assertIsNone(da.installed_at)
        self.assertIsNone(da.os_version_at_install_time)
        self.assertEqual(da.unique_install_identifier, "")
        # new da
        da2 = da_qs[1]
        self.assertNotEqual(da2, da)
        self.assertEqual(da2.artifact_version, profile_av2)
        self.assertEqual(da2.status, TargetArtifact.Status.FAILED)
        self.assertIsNone(da2.installed_at)
        self.assertIsNone(da2.os_version_at_install_time)
        self.assertEqual(da2.unique_install_identifier, "")

    # update_target_artifacts_from_status_report

    @patch("zentral.contrib.mdm.artifacts.datetime")
    def test_update_target_artifacts_from_status_report_installed(self, patched_datetime):
        patched_datetime.utcnow.return_value = datetime(2001, 2, 3, 4, 5, 6)
        _, profile_a, (profile_av,) = self._force_blueprint_artifact()
        status_report = self._build_status_report([(profile_av, True, True)])
        self.enrolled_device.os_version = "10.5.2"
        target = Target(self.enrolled_device)
        target.update_target_artifacts_with_status_report(status_report)
        serialized_av = target._serialized_target_artifacts[str(profile_a.pk)]["versions"][str(profile_av.pk)]
        self.assertEqual(
            serialized_av,
            (TargetArtifact.Status.INSTALLED, datetime(2001, 2, 3, 4, 5, 6), (10, 5, 2))
        )

    @patch("zentral.contrib.mdm.artifacts.datetime")
    def test_update_target_artifacts_from_status_report_uninstalled(self, patched_datetime):
        patched_datetime.utcnow.return_value = datetime(2001, 2, 3, 4, 5, 6)
        _, profile_a, (profile_av,) = self._force_blueprint_artifact()
        status_report = self._build_status_report([(profile_av, True, False)])
        self.enrolled_device.os_version = "10.5.2"
        target = Target(self.enrolled_device)
        target.update_target_artifacts_with_status_report(status_report)
        serialized_av = target._serialized_target_artifacts[str(profile_a.pk)]["versions"][str(profile_av.pk)]
        self.assertEqual(
            serialized_av,
            (TargetArtifact.Status.UNINSTALLED, None, (0, 0, 0))
        )

    @patch("zentral.contrib.mdm.artifacts.datetime")
    def test_update_target_artifacts_from_status_report_failed(self, patched_datetime):
        patched_datetime.utcnow.return_value = datetime(2001, 2, 3, 4, 5, 6)
        _, profile_a, (profile_av,) = self._force_blueprint_artifact()
        status_report = self._build_status_report([(profile_av, False, False)])
        self.enrolled_device.os_version = "10.5.2"
        target = Target(self.enrolled_device)
        target.update_target_artifacts_with_status_report(status_report)
        serialized_av = target._serialized_target_artifacts[str(profile_a.pk)]["versions"][str(profile_av.pk)]
        self.assertEqual(
            serialized_av,
            (TargetArtifact.Status.FAILED, None, (0, 0, 0))
        )

    def test_update_target_artifacts_from_status_report_cleanup(self):
        _, profile_a, (profile_av,) = self._force_blueprint_artifact()
        target = Target(self.enrolled_device)
        target.update_target_artifact(profile_av, TargetArtifact.Status.INSTALLED)
        self.assertEqual(
            DeviceArtifact.objects.filter(
                enrolled_device=self.enrolled_device,
                artifact_version=profile_av,
                status=TargetArtifact.Status.INSTALLED
            ).count(),
            1
        )
        status_report = self._build_status_report([])
        target.update_target_artifacts_with_status_report(status_report)
        self.assertEqual(DeviceArtifact.objects.filter(enrolled_device=self.enrolled_device).count(), 0)

    def test_update_target_artifacts_from_status_report_missing_configurations_noop(self):
        _, profile_a, (profile_av,) = self._force_blueprint_artifact()
        target = Target(self.enrolled_device)
        target.update_target_artifact(profile_av, TargetArtifact.Status.INSTALLED)
        da_qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version=profile_av,
            status=TargetArtifact.Status.INSTALLED
        )
        self.assertEqual(da_qs.count(), 1)
        target.update_target_artifacts_with_status_report({})
        self.assertEqual(da_qs.count(), 1)

    # test update client capabilities

    def test_update_target_with_status_report(self):
        target = Target(self.enrolled_device)
        status_report = self._build_status_report([])
        self.assertIsNone(target.client_capabilities)
        target.update_target_with_status_report(status_report)
        self.assertEqual(target.client_capabilities,
                         status_report["StatusItems"]["management"]["client-capabilities"])
