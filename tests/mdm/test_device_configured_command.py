from datetime import timedelta
from unittest.mock import patch
from django.test import TestCase
from django.utils import timezone
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import DeviceConfigured
from zentral.contrib.mdm.commands.scheduling import (_await_declarations_delay,
                                                     _finish_dep_enrollment_configuration,
                                                     _get_next_queued_command)
from zentral.contrib.mdm.models import (Artifact, Channel, Command,
                                        DEFAULT_AWAIT_DECLARATIONS_TIMEOUT, DeviceCommand,
                                        RequestStatus, TargetArtifact)
from .utils import (build_status_report, force_blueprint_artifact, force_dep_enrollment_session,
                    force_ota_enrollment_session)


class DeviceConfiguredCommandTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.dep_enrollment_session, cls.device_udid, cls.serial_number = force_dep_enrollment_session(
            cls.mbu,
            authenticated=True,
            completed=True,
        )
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device

    # verify_channel_and_device

    def test_verify_channel_and_device_ok(self):
        self.enrolled_device.awaiting_configuration = True
        self.assertTrue(DeviceConfigured.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_user_channel_not_ok(self):
        self.enrolled_device.awaiting_configuration = True
        self.assertFalse(DeviceConfigured.verify_channel_and_device(
            Channel.USER,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_awaiting_configuration_none_not_ok(self):
        self.assertIsNone(self.enrolled_device.awaiting_configuration)
        self.assertFalse(DeviceConfigured.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_awaiting_configuration_false_not_ok(self):
        self.enrolled_device.awaiting_configuration = False
        self.assertFalse(DeviceConfigured.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    # build_command

    def test_build_command(self):
        self.enrolled_device.awaiting_configuration = True
        cmd = DeviceConfigured.create_for_device(
            self.enrolled_device,
            queue=True
        )
        self.assertEqual(cmd.build_command(), {})

    # process_response

    def test_process_acknowledged_response(self):
        self.enrolled_device.awaiting_configuration = True
        cmd = DeviceConfigured.create_for_device(self.enrolled_device)
        cmd.process_response(
            {"UDID": self.enrolled_device.udid,
             "Status": "Acknowledged",
             "CommandUUID": str(cmd.uuid).upper()},
            self.dep_enrollment_session,
            self.mbu
        )
        cmd.db_command.refresh_from_db()
        self.assertEqual(cmd.status, Command.Status.ACKNOWLEDGED)
        self.assertEqual(cmd.db_command.status, Command.Status.ACKNOWLEDGED)
        self.enrolled_device.refresh_from_db()
        self.assertFalse(self.enrolled_device.awaiting_configuration)

    # _finish_dep_enrollment_configuration

    def test_device_configured_already_done(self):
        self.enrolled_device.awaiting_configuration = False
        self.assertIsNone(_finish_dep_enrollment_configuration(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_device_configured_notnow_ok(self):
        self.enrolled_device.awaiting_configuration = True
        command = _finish_dep_enrollment_configuration(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.NOT_NOW,
        )
        self.assertIsInstance(command, DeviceConfigured)
        self.assertEqual(command.channel, Channel.DEVICE)

    def test_device_configured(self):
        self.enrolled_device.awaiting_configuration = True
        command = _finish_dep_enrollment_configuration(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(command, DeviceConfigured)
        self.assertEqual(command.channel, Channel.DEVICE)

    # _finish_dep_enrollment_configuration, awaiting the declarations

    def _force_setup_assistant_declaration(self):
        blueprint_artifact, _, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CONFIGURATION,
            install_during_setup_assistant=True,
        )
        self.enrolled_device.blueprint = blueprint_artifact.blueprint
        self.enrolled_device.os_version = "13.1"
        self.enrolled_device.awaiting_configuration = True
        self.enrolled_device.declarative_management = True
        self.enrolled_device.save()
        return artifact_version

    def _finish(self):
        return _finish_dep_enrollment_configuration(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )

    def _report(self, artifact_version, status):
        Target(self.enrolled_device).update_target_artifact(artifact_version, status)

    def _device_configured_commands(self):
        return DeviceCommand.objects.filter(name=DeviceConfigured.get_db_name(),
                                            enrolled_device=self.enrolled_device)

    def test_device_configured_queued_while_declaration_not_reported(self):
        self._force_setup_assistant_declaration()
        self.assertIsNone(self._finish())
        db_command = self._device_configured_commands().get()
        self.assertIsNone(db_command.time)
        # the notification worker picks it up at the deadline
        self.assertGreater(db_command.not_before, timezone.now())

    def test_device_configured_still_queued_while_declaration_awaiting_confirmation(self):
        artifact_version = self._force_setup_assistant_declaration()
        self.assertIsNone(self._finish())
        self._report(artifact_version, TargetArtifact.Status.AWAITING_CONFIRMATION)
        # the device is still validating it
        self.assertIsNone(self._finish())
        self.assertIsNone(self._device_configured_commands().get().time)

    def test_device_configured_declaration_installed(self):
        artifact_version = self._force_setup_assistant_declaration()
        self._report(artifact_version, TargetArtifact.Status.INSTALLED)
        self.assertIsInstance(self._finish(), DeviceConfigured)

    def test_device_configured_declaration_failed(self):
        artifact_version = self._force_setup_assistant_declaration()
        self._report(artifact_version, TargetArtifact.Status.FAILED)
        self.assertIsInstance(self._finish(), DeviceConfigured)

    def test_device_configured_declaration_valid_but_inactive(self):
        artifact_version = self._force_setup_assistant_declaration()
        # valid but inactive is reported as uninstalled, and is a terminal state
        self._report(artifact_version, TargetArtifact.Status.UNINSTALLED)
        self.assertIsInstance(self._finish(), DeviceConfigured)

    def test_device_configured_queued_command_sent_once_reported(self):
        artifact_version = self._force_setup_assistant_declaration()
        self.assertIsNone(self._finish())
        queued_uuid = self._device_configured_commands().get().uuid
        self._report(artifact_version, TargetArtifact.Status.INSTALLED)
        command = self._finish()
        self.assertIsInstance(command, DeviceConfigured)
        # the queued command is sent, a second one is not created
        self.assertEqual(command.uuid, queued_uuid)
        self.assertIsNotNone(self._device_configured_commands().get().time)

    def test_device_configured_queued_command_sent_once_deadline_passed(self):
        self._force_setup_assistant_declaration()
        self.assertIsNone(self._finish())
        self._device_configured_commands().update(not_before=timezone.now() - timedelta(seconds=1))
        command = _get_next_queued_command(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(command, DeviceConfigured)

    def test_device_configured_no_declarative_management(self):
        self._force_setup_assistant_declaration()
        self.enrolled_device.declarative_management = False
        self.assertIsInstance(self._finish(), DeviceConfigured)

    # _await_declarations_delay

    def test_await_declarations_delay(self):
        self.dep_enrollment_session.dep_enrollment.await_declarations_timeout = 7
        self.assertEqual(_await_declarations_delay(self.dep_enrollment_session), 420)

    def test_await_declarations_delay_without_dep_enrollment(self):
        session, _, _ = force_ota_enrollment_session(self.mbu, authenticated=True, completed=True)
        self.assertEqual(_await_declarations_delay(session), DEFAULT_AWAIT_DECLARATIONS_TIMEOUT * 60)

    # the device is poked as soon as it reports the declarations

    def _force_setup_assistant_legacy_profile(self):
        blueprint_artifact, _, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.PROFILE,
            install_during_setup_assistant=True,
        )
        blueprint = blueprint_artifact.blueprint
        blueprint.legacy_profiles_via_ddm = True
        blueprint.save()
        self.enrolled_device.blueprint = blueprint
        self.enrolled_device.os_version = "13.1"
        self.enrolled_device.awaiting_configuration = True
        self.enrolled_device.declarative_management = True
        self.enrolled_device.save()
        return artifact_version

    @patch("zentral.contrib.mdm.artifacts.send_enrolled_device_notification")
    def test_status_report_notifies_the_device_and_releases_it(self, send_enrolled_device_notification):
        artifact_version = self._force_setup_assistant_legacy_profile()
        # nothing reported yet, the command is queued with the deadline
        self.assertIsNone(self._finish())
        self.assertIsNone(self._device_configured_commands().get().time)
        send_enrolled_device_notification.assert_not_called()
        # the device reports the declaration on the status channel
        status_report = build_status_report([(artifact_version, True, True, None)])
        with self.captureOnCommitCallbacks(execute=True):
            Target(self.enrolled_device).update_target_with_status_report(status_report)
        # it is notified right away, so it comes back without waiting for the deadline
        send_enrolled_device_notification.assert_called_once_with(self.enrolled_device)
        command = self._finish()
        self.assertIsInstance(command, DeviceConfigured)
        self.assertIsNotNone(self._device_configured_commands().get().time)
