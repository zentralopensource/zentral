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
        device_updated = False
        if not self.enrolled_device.declarative_management:
            self.enrolled_device.declarative_management = True
            device_updated = True
        if (
            self.enrolled_device.blueprint
            and self.enrolled_device.declarations_token != self.enrolled_device.blueprint.declarations_token
        ):
            self.enrolled_device.declarations_token = self.enrolled_device.blueprint.declarations_token
            device_updated = True
        if device_updated:
            self.enrolled_device.save()


register_command(DeclarativeManagement)
