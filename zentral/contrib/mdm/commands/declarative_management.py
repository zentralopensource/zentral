import logging
from zentral.contrib.mdm.models import Channel, Platform
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.declarative_management")


class DeclarativeManagement(Command):
    request_type = "DeclarativeManagement"
    allowed_channel = Channel.Device
    allowed_platform = (Platform.iOS, Platform.iPadOS, Platform.macOS, Platform.tvOS)
    allowed_in_user_enrollment = True

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        # TODO implement on user channel
        if channel == Channel.User:
            return False
        return (
            (
                enrolled_device.platform in (Platform.iOS.name, Platform.iPadOS.name)
                and (
                    (
                        enrolled_device.user_enrollment
                        and enrolled_device.comparable_os_version >= (15,)
                    ) or (
                        not enrolled_device.user_enrollment
                        and enrolled_device.comparable_os_version >= (16,)
                    )
                )
            ) or (
                enrolled_device.platform == Platform.macOS.name
                and enrolled_device.comparable_os_version >= (13,)
            ) or (
                enrolled_device.platform == Platform.tvOS.name
                and enrolled_device.comparable_os_version >= (16,)
            )
        )

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
