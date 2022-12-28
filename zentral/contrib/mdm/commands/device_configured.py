import logging
from zentral.contrib.mdm.models import Channel
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.device_configured")


class DeviceConfigured(Command):
    request_type = "DeviceConfigured"

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            channel == Channel.Device
            and enrolled_device.awaiting_configuration
        )

    def command_acknowledged(self):
        if self.enrolled_device.awaiting_configuration:
            # TODO event
            self.enrolled_device.awaiting_configuration = False
            self.enrolled_device.save()
        else:
            logger.error("Enrolled device %s: not awaiting configuration", self.enrolled_device.udid)


register_command(DeviceConfigured)
