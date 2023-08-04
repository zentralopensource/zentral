import logging
from uuid import uuid4
from django import forms
from django.db import transaction
from django.utils.crypto import get_random_string
from zentral.contrib.mdm.events import post_recovery_password_event
from zentral.contrib.mdm.models import Channel, Platform
from zentral.core.secret_engines import decrypt_str, encrypt_str
from .base import register_command, Command, CommandBaseForm


logger = logging.getLogger("zentral.contrib.mdm.commands.set_recovery_lock")


def validate_recovery_password(password):
    if len(password) < 8:
        raise forms.ValidationError("The password must be at least 8 characters long.")
    if len(password) > 32:
        raise forms.ValidationError("The password must be at most 32 characters long.")
    if not all(32 <= ord(c) < 127 for c in password):
        raise forms.ValidationError(
            "The characters in this value must consist of low-ASCII, printable characters (0x20 through 0x7E) "
            "to ensure that all characters are enterable on the EFI login screen."
        )


def generate_password(length=12):
    # TODO: increase the entropy by using the full ASCII range without risking having a password impossible to type?
    return get_random_string(length)


def get_secret_engine_kwargs(uuid):
    return {"model": "mdm.devicecommand", "field": "new_password", "uuid": str(uuid)}


class SetRecoveryLockForm(CommandBaseForm):
    new_password = forms.CharField(
        label="New password", required=False, strip=True,
        validators=[validate_recovery_password]
    )

    def clean_new_password(self):
        new_password = self.cleaned_data.get("new_password")
        if not new_password and not self.enrolled_device.recovery_password:
            raise forms.ValidationError("No current recovery lock set: this field is required.")
        return new_password

    def get_command_kwargs(self, uuid):
        kwargs = {}
        new_password = self.cleaned_data.get("new_password")
        if new_password:
            kwargs["new_password"] = encrypt_str(self.cleaned_data["new_password"], **get_secret_engine_kwargs(uuid))
        return kwargs


class SetRecoveryLock(Command):
    request_type = "SetRecoveryLock"
    display_name = "Set recovery lock"
    reschedule_notnow = True
    form_class = SetRecoveryLockForm

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

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            channel == Channel.DEVICE
            and enrolled_device.platform == Platform.MACOS
            and enrolled_device.apple_silicon
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
        current_password = self.enrolled_device.get_recovery_password()
        new_password = self.load_new_password()
        operation = None
        if new_password:
            if current_password:
                if current_password != new_password:
                    operation = "update"
            else:
                operation = "set"
        elif current_password:
            operation = "clear"
        if operation:
            self.enrolled_device.set_recovery_password(new_password)
            self.enrolled_device.save()
            transaction.on_commit(lambda: post_recovery_password_event(
                self, password_type="recovery_lock", operation=operation
            ))


register_command(SetRecoveryLock)
