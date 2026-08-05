import logging
from uuid import uuid4
from django import forms
from zentral.contrib.mdm.models import Channel, Platform
from zentral.core.secret_engines import decrypt_str, encrypt_str
from .base import register_command, Command, CommandBaseForm
from .restart_device import RestartDevice
from .set_recovery_lock import generate_password, get_secret_engine_kwargs, validate_recovery_password


logger = logging.getLogger("zentral.contrib.mdm.commands.set_recovery_lock")


class SetFirmwarePasswordForm(CommandBaseForm):
    new_password = forms.CharField(
        label="New password", required=False, strip=True,
        validators=[validate_recovery_password]
    )

    def clean_new_password(self):
        new_password = self.cleaned_data.get("new_password")
        if not new_password and not self.enrolled_device.recovery_password:
            raise forms.ValidationError("No current firmware password set: this field is required.")
        return new_password

    def get_command_kwargs(self, uuid):
        kwargs = {}
        new_password = self.cleaned_data.get("new_password")
        if new_password:
            kwargs["new_password"] = encrypt_str(self.cleaned_data["new_password"], **get_secret_engine_kwargs(uuid))
        return kwargs


class SetFirmwarePassword(Command):
    request_type = "SetFirmwarePassword"
    display_name = "Set firmware password"
    reschedule_notnow = True
    verify_target_before_delivery = True
    form_class = SetFirmwarePasswordForm
    audit_secret_kwargs = ("new_password",)

    @classmethod
    def create_for_automatic_scheduling(cls, target, password=None):
        if not password:
            password = generate_password()
        uuid = uuid4()
        return super().create_for_target(
            target,
            kwargs={"new_password": encrypt_str(password, **get_secret_engine_kwargs(uuid))},
            uuid=uuid,
        )

    @classmethod
    def create_for_auto_rotation(cls, target, delay_min):
        if cls.is_queued_for_target(target):
            logger.warning("Set firmware password command for device %s already scheduled",
                           target.enrolled_device)
            return
        uuid = uuid4()
        password = generate_password()
        return super().create_for_target(
            target,
            kwargs={"new_password": encrypt_str(password, **get_secret_engine_kwargs(uuid))},
            queue=True, delay=delay_min * 60,
            uuid=uuid,
        )

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            channel == Channel.DEVICE
            and enrolled_device.platform == Platform.MACOS
            and not enrolled_device.user_enrollment
            and not enrolled_device.apple_silicon
            and not enrolled_device.pending_firmware_password  # cannot send the command if there is a pending change
        )

    def load_new_password(self):
        new_password = self.db_command.kwargs.get("new_password")
        if new_password:
            return decrypt_str(new_password, **get_secret_engine_kwargs(self.uuid))
        else:
            return ""

    def build_command(self):
        payload = {"NewPassword": self.load_new_password()}
        current_password = self.enrolled_device.get_recovery_password()
        if current_password:
            payload["CurrentPassword"] = current_password
        return payload

    def command_acknowledged(self):
        password_changed = self.response.get("SetFirmwarePassword", {}).get("PasswordChanged")
        if not password_changed:
            logger.error("Enrolled device %s firmware password was not changed by command %s",
                         self.enrolled_device, self.uuid)
            return
        self.enrolled_device.set_pending_firmware_password(self.load_new_password())
        self.enrolled_device.save()
        # schedule a reboot notification for the pending firmware password to be applied
        RestartDevice.create_for_target(self.target, kwargs={"NotifyUser": True}, queue=True, delay=0)


register_command(SetFirmwarePassword)
