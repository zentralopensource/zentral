import uuid
from unittest.mock import patch
from django.test import TestCase
from django.utils import timezone
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.app_install_checks import (AppInstallCheckError,
                                                    get_app_install_check,
                                                    iter_unchecked_app_target_artifacts,
                                                    notify_target,
                                                    queue_app_install_check)
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import InstalledApplicationList, ManagedApplicationList
from zentral.contrib.mdm.models import (Artifact, Channel, Command, DeviceArtifact, DeviceCommand,
                                        Platform, TargetArtifact, UserArtifact, UserCommand)
from .utils import force_artifact, force_dep_enrollment_session, force_enrolled_user


class AppInstallChecksTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.dep_enrollment_session, _, _ = force_dep_enrollment_session(
            cls.mbu, authenticated=True, completed=True, realm_user=True
        )
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device
        cls.enrolled_user = force_enrolled_user(cls.enrolled_device)

    # utils

    def _force_store_app_version(self, bundle_id="com.example.app", channel=Channel.DEVICE):
        _, [artifact_version] = force_artifact(artifact_type=Artifact.Type.STORE_APP, channel=channel)
        asset = artifact_version.store_app.location_asset.asset
        asset.bundle_id = bundle_id
        asset.save()
        return artifact_version

    def _force_enterprise_app_version(self, bundles=None):
        _, [artifact_version] = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        if bundles is None:
            bundles = [{"id": "com.example.app", "version_str": "1.0"}]
        artifact_version.enterprise_app.bundles = bundles
        artifact_version.enterprise_app.save()
        return artifact_version

    def _force_device_artifact(self, artifact_version, status=TargetArtifact.Status.AWAITING_CONFIRMATION):
        return DeviceArtifact.objects.create(
            enrolled_device=self.enrolled_device,
            artifact_version=artifact_version,
            status=status,
        )

    def _force_check_command(self, artifact_version, name="ManagedApplicationList",
                             sent=False, status=None, model=DeviceCommand, **kwargs):
        if not kwargs:
            kwargs = {"enrolled_device": self.enrolled_device}
        now = timezone.now()
        return model.objects.create(
            uuid=uuid.uuid4(),
            name=name,
            artifact_version=artifact_version,
            time=now if sent else None,
            result_time=now if status else None,
            status=status,
            **kwargs,
        )

    def _unchecked(self, serial_numbers=None):
        return list(iter_unchecked_app_target_artifacts(serial_numbers))

    # iter_unchecked_app_target_artifacts

    def test_unchecked_store_app(self):
        artifact_version = self._force_store_app_version()
        device_artifact = self._force_device_artifact(artifact_version)
        [(target, target_artifact)] = self._unchecked()
        self.assertTrue(target.is_device)
        self.assertEqual(target.enrolled_device, self.enrolled_device)
        self.assertEqual(target_artifact, device_artifact)

    def test_unchecked_enterprise_app(self):
        artifact_version = self._force_enterprise_app_version()
        device_artifact = self._force_device_artifact(artifact_version)
        [(_, target_artifact)] = self._unchecked()
        self.assertEqual(target_artifact, device_artifact)

    def test_unchecked_skips_other_statuses(self):
        for status in TargetArtifact.Status:
            if status == TargetArtifact.Status.AWAITING_CONFIRMATION:
                continue
            self._force_device_artifact(self._force_store_app_version(), status=status)
        self.assertEqual(self._unchecked(), [])

    def test_unchecked_skips_other_artifact_types(self):
        _, [artifact_version] = force_artifact(artifact_type=Artifact.Type.PROFILE)
        self._force_device_artifact(artifact_version)
        self.assertEqual(self._unchecked(), [])

    def test_unchecked_skips_queued_check(self):
        artifact_version = self._force_store_app_version()
        self._force_device_artifact(artifact_version)
        self._force_check_command(artifact_version)
        self.assertEqual(self._unchecked(), [])

    def test_unchecked_skips_in_flight_check(self):
        artifact_version = self._force_store_app_version()
        self._force_device_artifact(artifact_version)
        self._force_check_command(artifact_version, sent=True)
        self.assertEqual(self._unchecked(), [])

    def test_unchecked_skips_not_now_check(self):
        artifact_version = self._force_store_app_version()
        self._force_device_artifact(artifact_version)
        self._force_check_command(artifact_version, sent=True, status=Command.Status.NOT_NOW)
        self.assertEqual(self._unchecked(), [])

    def test_unchecked_ignores_acknowledged_check(self):
        artifact_version = self._force_store_app_version()
        device_artifact = self._force_device_artifact(artifact_version)
        self._force_check_command(artifact_version, sent=True, status=Command.Status.ACKNOWLEDGED)
        [(_, target_artifact)] = self._unchecked()
        self.assertEqual(target_artifact, device_artifact)

    def test_unchecked_ignores_check_for_other_artifact_version(self):
        artifact_version = self._force_store_app_version()
        device_artifact = self._force_device_artifact(artifact_version)
        self._force_check_command(self._force_store_app_version())
        [(_, target_artifact)] = self._unchecked()
        self.assertEqual(target_artifact, device_artifact)

    def test_unchecked_ignores_other_commands(self):
        artifact_version = self._force_store_app_version()
        device_artifact = self._force_device_artifact(artifact_version)
        self._force_check_command(artifact_version, name="InstallApplication")
        [(_, target_artifact)] = self._unchecked()
        self.assertEqual(target_artifact, device_artifact)

    def test_unchecked_serial_number_filter(self):
        artifact_version = self._force_store_app_version()
        device_artifact = self._force_device_artifact(artifact_version)
        self.assertEqual(self._unchecked([get_random_string(12)]), [])
        [(_, target_artifact)] = self._unchecked([self.enrolled_device.serial_number])
        self.assertEqual(target_artifact, device_artifact)

    def test_unchecked_user_channel(self):
        artifact_version = self._force_store_app_version(channel=Channel.USER)
        user_artifact = UserArtifact.objects.create(
            enrolled_user=self.enrolled_user,
            artifact_version=artifact_version,
            status=TargetArtifact.Status.AWAITING_CONFIRMATION,
        )
        [(target, target_artifact)] = self._unchecked()
        self.assertFalse(target.is_device)
        self.assertEqual(target.enrolled_user, self.enrolled_user)
        self.assertEqual(target_artifact, user_artifact)
        self.assertEqual(self._unchecked([get_random_string(12)]), [])
        self._force_check_command(artifact_version, model=UserCommand, enrolled_user=self.enrolled_user)
        self.assertEqual(self._unchecked(), [])

    def test_unchecked_ordered_by_target(self):
        first = self._force_device_artifact(self._force_store_app_version())
        second = self._force_device_artifact(self._force_enterprise_app_version())
        self.assertEqual([ta for _, ta in self._unchecked()], [first, second])

    # get_app_install_check

    def test_get_app_install_check_store_app(self):
        artifact_version = self._force_store_app_version(bundle_id="com.example.store")
        command_class, kwargs = get_app_install_check(artifact_version)
        self.assertEqual(command_class, ManagedApplicationList)
        self.assertEqual(kwargs, {"identifiers": ["com.example.store"]})

    def test_get_app_install_check_store_app_without_bundle_id(self):
        artifact_version = self._force_store_app_version(bundle_id=None)
        with self.assertRaises(AppInstallCheckError) as cm:
            get_app_install_check(artifact_version)
        self.assertEqual(str(cm.exception), "Asset without bundle ID")

    def test_get_app_install_check_enterprise_app(self):
        artifact_version = self._force_enterprise_app_version(
            bundles=[{"id": "com.example.one", "version_str": "1.0"},
                     {"id": "com.example.two", "version_str": "2.0"}]
        )
        command_class, kwargs = get_app_install_check(artifact_version)
        self.assertEqual(command_class, InstalledApplicationList)
        self.assertEqual(kwargs, {"apps_to_check": [{"Identifier": "com.example.one", "ShortVersion": "1.0"},
                                                    {"Identifier": "com.example.two", "ShortVersion": "2.0"}]})

    def test_get_app_install_check_enterprise_app_without_bundles(self):
        artifact_version = self._force_enterprise_app_version(bundles=[])
        with self.assertRaises(AppInstallCheckError) as cm:
            get_app_install_check(artifact_version)
        self.assertEqual(str(cm.exception), "Enterprise app without bundles")

    def test_get_app_install_check_unsupported_type(self):
        _, [artifact_version] = force_artifact(artifact_type=Artifact.Type.PROFILE)
        with self.assertRaises(AppInstallCheckError) as cm:
            get_app_install_check(artifact_version)
        self.assertEqual(str(cm.exception), "Unsupported artifact type Profile")

    # queue_app_install_check

    def test_queue_app_install_check(self):
        artifact_version = self._force_store_app_version(bundle_id="com.example.store")
        self._force_device_artifact(artifact_version)
        target = Target(self.enrolled_device)
        command = queue_app_install_check(target, artifact_version)
        self.assertIsInstance(command, ManagedApplicationList)
        db_command = DeviceCommand.objects.get(enrolled_device=self.enrolled_device)
        self.assertEqual(db_command.name, "ManagedApplicationList")
        self.assertEqual(db_command.artifact_version, artifact_version)
        self.assertEqual(db_command.kwargs, {"identifiers": ["com.example.store"]})
        self.assertIsNone(db_command.time)
        self.assertIsNone(db_command.not_before)
        self.assertEqual(self._unchecked(), [])

    def test_queue_app_install_check_incompatible_target(self):
        artifact_version = self._force_store_app_version(channel=Channel.USER)
        self.enrolled_device.platform = Platform.IOS
        target = Target(self.enrolled_device, self.enrolled_user)
        with self.assertRaises(AppInstallCheckError) as cm:
            queue_app_install_check(target, artifact_version)
        self.assertEqual(str(cm.exception), "Incompatible target for ManagedApplicationList")
        self.assertEqual(UserCommand.objects.filter(enrolled_user=self.enrolled_user).count(), 0)

    # notify_target

    @patch("zentral.contrib.mdm.app_install_checks.send_enrolled_device_notification")
    def test_notify_device_target(self, send_enrolled_device_notification):
        send_enrolled_device_notification.return_value = (True, None)
        self.assertTrue(notify_target(Target(self.enrolled_device)))
        send_enrolled_device_notification.assert_called_once_with(self.enrolled_device)

    @patch("zentral.contrib.mdm.app_install_checks.send_enrolled_user_notification")
    def test_notify_user_target(self, send_enrolled_user_notification):
        send_enrolled_user_notification.return_value = (False, None)
        self.assertFalse(notify_target(Target(self.enrolled_device, self.enrolled_user)))
        send_enrolled_user_notification.assert_called_once_with(self.enrolled_user)

    @patch("zentral.contrib.mdm.app_install_checks.send_enrolled_device_notification")
    def test_notify_target_cannot_be_poked(self, send_enrolled_device_notification):
        self.enrolled_device.checkout_at = timezone.now()
        self.assertFalse(notify_target(Target(self.enrolled_device)))
        send_enrolled_device_notification.assert_not_called()
