import logging
from zentral.contrib.mdm.models import Channel, Platform
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.device_configured")


class DeviceConfigured(Command):
    request_type = "DeviceConfigured"
    allowed_channel = (Channel.Device, Channel.User)  # TODO verify
    allowed_platform = (Platform.iOS, Platform.iPadOS, Platform.macOS, Platform.tvOS)
    allowed_in_user_enrollment = False

    def command_acknowledged(self):
        if self.enrolled_device.awaiting_configuration:
            # TODO event
            self.enrolled_device.awaiting_configuration = False
            self.enrolled_device.save()
        else:
            logger.error("Enrolled device %s: not awaiting configuration", self.enrolled_device.udid)


register_command(DeviceConfigured)
