import json
import logging
import uuid
from zentral.contrib.mdm.models import Channel, Platform
from zentral.contrib.mdm.declarations import get_blueprint_tokens_response
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.declarative_management")


class DeclarativeManagement(Command):
    request_type = "DeclarativeManagement"

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        # TODO implement on user channel
        if channel == Channel.User:
            return False
        if not enrolled_device.blueprint:
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

    def load_kwargs(self):
        self.blueprint_pk = self.db_command.kwargs.get("blueprint_pk")
        self.declarations_token = None
        declarations_token = self.db_command.kwargs.get("declarations_token")
        if declarations_token:
            self.declarations_token = uuid.UUID(declarations_token)

    def build_command(self):
        blueprint = self.enrolled_device.blueprint
        tokens_response, declarations_token = get_blueprint_tokens_response(blueprint)
        # The declarations_token is stored when the command is built so that
        # the enrolled device can be updated when the command is acknowledged.
        # If the blueprint is updated after the command is sent, but before the
        # command is acknowledged, the enrolled device is updated with the
        # correct (and not current) declarations token.
        self.db_command.kwargs["blueprint_pk"] = self.blueprint_pk = blueprint.pk
        self.declarations_token = declarations_token
        self.db_command.kwargs["declarations_token"] = str(declarations_token)
        self.db_command.save()
        return {"Data": json.dumps(tokens_response).encode("utf-8")}

    def command_acknowledged(self):
        device_updated = False
        if not self.enrolled_device.declarative_management:
            self.enrolled_device.declarative_management = True
            device_updated = True
        if self.declarations_token and self.enrolled_device.declarations_token != self.declarations_token:
            self.enrolled_device.declarations_token = self.declarations_token
            device_updated = True
        if device_updated:
            self.enrolled_device.save()


register_command(DeclarativeManagement)
