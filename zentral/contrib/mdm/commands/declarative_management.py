import logging
from zentral.contrib.mdm.models import Channel, Platform
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.declarative_management")


class DeclarativeManagement(Command):
    request_type = "DeclarativeManagement"
    allowed_channel = Channel.Device
    allowed_platform = (Platform.iOS, Platform.iPadOS)
    allowed_in_user_enrollment = True

    def command_acknowledged(self):
        if self.enrolled_device.declarative_management:
            logger.error("Enrolled device %s: declarative management already set", self.enrolled_device.pk)
        else:
            self.enrolled_device.declarative_management = True
            self.enrolled_device.save()


register_command(DeclarativeManagement)
