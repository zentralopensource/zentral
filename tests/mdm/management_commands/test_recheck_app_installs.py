from io import StringIO
from unittest.mock import patch
from django.core.management import call_command
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.models import Artifact, DeviceArtifact, DeviceCommand, TargetArtifact
from ..utils import force_artifact, force_dep_enrollment_session


class RecheckAppInstallsCommandTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.dep_enrollment_session, _, _ = force_dep_enrollment_session(
            cls.mbu, authenticated=True, completed=True, realm_user=True
        )
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device

    def _force_stuck_store_app(self, bundle_id="com.example.app"):
        artifact, [artifact_version] = force_artifact(artifact_type=Artifact.Type.STORE_APP)
        asset = artifact_version.store_app.location_asset.asset
        asset.bundle_id = bundle_id
        asset.save()
        device_artifact = DeviceArtifact.objects.create(
            enrolled_device=self.enrolled_device,
            artifact_version=artifact_version,
            status=TargetArtifact.Status.AWAITING_CONFIRMATION,
        )
        return artifact, artifact_version, device_artifact

    def _queued_checks(self):
        return DeviceCommand.objects.filter(enrolled_device=self.enrolled_device, time__isnull=True)

    @patch("zentral.contrib.mdm.app_install_checks.send_enrolled_device_notification")
    def test_nothing_to_check(self, send_enrolled_device_notification):
        out = StringIO()
        call_command('recheck_app_installs', stdout=out)
        self.assertEqual(out.getvalue(), "0 install check(s) queued, 0 skipped\n")
        send_enrolled_device_notification.assert_not_called()

    @patch("zentral.contrib.mdm.app_install_checks.send_enrolled_device_notification")
    def test_queue_and_notify(self, send_enrolled_device_notification):
        send_enrolled_device_notification.return_value = (True, None)
        artifact, artifact_version, device_artifact = self._force_stuck_store_app()
        out = StringIO()
        call_command('recheck_app_installs', stdout=out)
        serial_number = self.enrolled_device.serial_number
        self.assertEqual(
            out.getvalue(),
            f"Queued ManagedApplicationList for {serial_number} {artifact.name} v1"
            f" since {device_artifact.updated_at:%Y-%m-%d}\n"
            f"Notified {serial_number}\n"
            "1 install check(s) queued, 0 skipped\n"
        )
        [db_command] = self._queued_checks()
        self.assertEqual(db_command.name, "ManagedApplicationList")
        self.assertEqual(db_command.artifact_version, artifact_version)
        self.assertEqual(db_command.kwargs, {"identifiers": ["com.example.app"]})
        send_enrolled_device_notification.assert_called_once_with(self.enrolled_device)

    @patch("zentral.contrib.mdm.app_install_checks.send_enrolled_device_notification")
    def test_one_notification_per_device(self, send_enrolled_device_notification):
        send_enrolled_device_notification.return_value = (False, None)
        self._force_stuck_store_app()
        self._force_stuck_store_app()
        out = StringIO()
        call_command('recheck_app_installs', stdout=out)
        self.assertEqual(self._queued_checks().count(), 2)
        send_enrolled_device_notification.assert_called_once_with(self.enrolled_device)
        self.assertIn(f"Could not notify {self.enrolled_device.serial_number}\n", out.getvalue())
        self.assertTrue(out.getvalue().endswith("2 install check(s) queued, 0 skipped\n"))

    @patch("zentral.contrib.mdm.app_install_checks.send_enrolled_device_notification")
    def test_no_notification(self, send_enrolled_device_notification):
        self._force_stuck_store_app()
        out = StringIO()
        call_command('recheck_app_installs', '--no-notification', stdout=out)
        self.assertEqual(self._queued_checks().count(), 1)
        send_enrolled_device_notification.assert_not_called()
        self.assertNotIn("otif", out.getvalue())

    @patch("zentral.contrib.mdm.app_install_checks.send_enrolled_device_notification")
    def test_dry_run(self, send_enrolled_device_notification):
        artifact, _, device_artifact = self._force_stuck_store_app()
        out = StringIO()
        call_command('recheck_app_installs', '--dry-run', stdout=out)
        self.assertEqual(
            out.getvalue(),
            f"Would queue ManagedApplicationList for {self.enrolled_device.serial_number} {artifact.name} v1"
            f" since {device_artifact.updated_at:%Y-%m-%d}\n"
            "1 install check(s) to queue, 0 skipped\n"
        )
        self.assertEqual(self._queued_checks().count(), 0)
        send_enrolled_device_notification.assert_not_called()

    @patch("zentral.contrib.mdm.app_install_checks.send_enrolled_device_notification")
    def test_skipped(self, send_enrolled_device_notification):
        artifact, _, device_artifact = self._force_stuck_store_app(bundle_id=None)
        out = StringIO()
        call_command('recheck_app_installs', stdout=out)
        self.assertEqual(
            out.getvalue(),
            f"Skipped {self.enrolled_device.serial_number} {artifact.name} v1"
            f" since {device_artifact.updated_at:%Y-%m-%d}: Asset without bundle ID\n"
            "0 install check(s) queued, 1 skipped\n"
        )
        self.assertEqual(self._queued_checks().count(), 0)
        send_enrolled_device_notification.assert_not_called()

    @patch("zentral.contrib.mdm.app_install_checks.send_enrolled_device_notification")
    def test_serial_number_filter(self, send_enrolled_device_notification):
        send_enrolled_device_notification.return_value = (True, None)
        self._force_stuck_store_app()
        out = StringIO()
        call_command('recheck_app_installs', '--serial-number', get_random_string(12), stdout=out)
        self.assertEqual(out.getvalue(), "0 install check(s) queued, 0 skipped\n")
        self.assertEqual(self._queued_checks().count(), 0)
        call_command('recheck_app_installs', '--serial-number', self.enrolled_device.serial_number, stdout=out)
        self.assertEqual(self._queued_checks().count(), 1)
        send_enrolled_device_notification.assert_called_once_with(self.enrolled_device)

    def test_quiet(self):
        self._force_stuck_store_app()
        out = StringIO()
        call_command('recheck_app_installs', '--no-notification', '--verbosity', '0', stdout=out)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(self._queued_checks().count(), 1)
