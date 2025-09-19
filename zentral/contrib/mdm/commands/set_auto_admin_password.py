import logging
from uuid import uuid4
from django import forms
from django.db import transaction
from django.utils.crypto import get_random_string
from zentral.contrib.mdm.events import post_admin_password_updated_event
from zentral.contrib.mdm.models import Channel, DEPEnrollment, DeviceCommand, Platform
from zentral.core.secret_engines import decrypt_str, encrypt_str
from zentral.utils.passwords import build_password_hash_dict, serialize_password_hash_dict
from .base import register_command, Command, CommandBaseForm


logger = logging.getLogger("zentral.contrib.mdm.commands.set_auto_admin_password")


ALLOWED_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # Removed 1, I, 0, O


def generate_password(complexity):
    group_length = 6
    group_count = 4
    if complexity <= 1:
        group_count = 2
    elif complexity <= 2:
        group_count = 3
    return "-".join(get_random_string(group_length, allowed_chars=ALLOWED_CHARS) for _ in range(group_count))


def get_password_complexity(enrolled_device):
    complexity = 3
    enrollment = enrolled_device.current_enrollment
    if isinstance(enrollment, DEPEnrollment):  # should always be the case
        complexity = enrollment.admin_password_complexity
    return complexity


def get_secret_engine_kwargs(uuid):
    return {"model": "mdm.devicecommand", "field": "new_password", "uuid": str(uuid)}


def get_command_kwargs(uuid, new_password=None, complexity=3):
    if not new_password:
        new_password = generate_password(complexity)
    return {"new_password": encrypt_str(new_password, **get_secret_engine_kwargs(uuid))}


class SetAutoAdminPasswordForm(CommandBaseForm):
    new_password = forms.CharField(
        label="New password", required=False, strip=True,
        help_text="Leave empty to set an auto-generated password.",
    )

    def get_command_kwargs(self, uuid):
        new_password = self.cleaned_data.get("new_password")
        complexity = get_password_complexity(self.enrolled_device)
        return get_command_kwargs(uuid, new_password, complexity)


class SetAutoAdminPassword(Command):
    request_type = "SetAutoAdminPassword"
    display_name = "Set auto admin password"
    reschedule_notnow = True
    form_class = SetAutoAdminPasswordForm

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            channel == Channel.DEVICE
            and enrolled_device.platform == Platform.MACOS
            and not enrolled_device.user_enrollment
            and enrolled_device.admin_guid
        )

    @classmethod
    def create_for_auto_rotation(cls, target, delay_min):
        if (
            DeviceCommand.objects.filter(
                name=cls.get_db_name(),
                enrolled_device=target.enrolled_device,
                time__isnull=True
            ).exists()
        ):
            logger.warning("Set auto admin password command for device %s already scheduled", target.enrolled_device)
            return
        uuid = uuid4()
        return super().create_for_target(
            target,
            kwargs=get_command_kwargs(uuid, complexity=get_password_complexity(target.enrolled_device)),
            queue=True, delay=delay_min * 60,
            uuid=uuid
        )

    def load_new_password(self):
        new_password = self.db_command.kwargs.get("new_password")
        return decrypt_str(new_password, **get_secret_engine_kwargs(self.uuid))

    def build_command(self):
        return {
            "GUID": self.enrolled_device.admin_guid,
            "passwordHash": serialize_password_hash_dict(build_password_hash_dict(self.load_new_password())),
        }

    def command_acknowledged(self):
        new_password = self.load_new_password()
        self.enrolled_device.set_admin_password(new_password)
        self.enrolled_device.save()
        transaction.on_commit(lambda: post_admin_password_updated_event(self))


register_command(SetAutoAdminPassword)
