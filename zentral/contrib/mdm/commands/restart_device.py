import logging
from django import forms
from zentral.contrib.mdm.models import Channel, Platform
from .base import register_command, Command, CommandBaseForm


logger = logging.getLogger("zentral.contrib.mdm.commands.restart_device")


class RestartDeviceForm(CommandBaseForm):
    notify_user = forms.BooleanField(label="Only notify user?", required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if (
            self.enrolled_device.platform != Platform.MACOS
            or self.enrolled_device.comparable_os_version < (11, 3)
        ):
            self.fields.pop("notify_user")

    def get_command_kwargs(self, uuid):
        kwargs = {}
        if self.cleaned_data.get("notify_user"):
            kwargs["NotifyUser"] = True
        return kwargs


class RestartDevice(Command):
    request_type = "RestartDevice"
    display_name = "Restart device"
    form_class = RestartDeviceForm

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            channel == Channel.DEVICE
            and not enrolled_device.user_enrollment
            and (
                enrolled_device.supervised
                or enrolled_device.platform == Platform.MACOS
            )
        )

    def build_command(self):
        payload = {}
        if self.db_command.kwargs.get("NotifyUser"):
            payload["NotifyUser"] = True
        return payload


register_command(RestartDevice)
