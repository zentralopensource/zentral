import json
import logging
from zentral.contrib.mdm.models import Platform
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.declarative_management")


class DeclarativeManagement(Command):
    request_type = "DeclarativeManagement"

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        if not enrolled_device.blueprint:
            return False
        comparable_os_version = enrolled_device.comparable_os_version
        return (
            (
                enrolled_device.platform in (Platform.IOS, Platform.IPADOS)
                and (
                    (
                        enrolled_device.user_enrollment
                        and comparable_os_version >= (15,)
                    ) or (
                        not enrolled_device.user_enrollment
                        and comparable_os_version >= (16,)
                    )
                )
            ) or (
                enrolled_device.platform == Platform.MACOS
                and comparable_os_version >= (13,)
            ) or (
                enrolled_device.platform == Platform.TVOS
                and comparable_os_version >= (16,)
            )
        )

    @classmethod
    def verify_target(cls, target):
        return not target.awaiting_configuration and super().verify_target(target)

    def load_kwargs(self):
        self.blueprint_pk = self.db_command.kwargs.get("blueprint_pk")
        self.declarations_token = self.db_command.kwargs.get("declarations_token")

    def build_command(self):
        tokens_response, declarations_token = self.target.sync_tokens
        # The declarations_token is stored when the command is built so that
        # the target can be updated when the command is acknowledged.
        # If the blueprint or scoping is updated after the command is sent, but before
        # the command is acknowledged, the target is updated with the
        # correct (and not current) declarations token.
        self.db_command.kwargs["blueprint_pk"] = self.blueprint_pk = self.target.blueprint.pk
        self.db_command.kwargs["declarations_token"] = self.declarations_token = declarations_token
        self.db_command.save()
        return {"Data": json.dumps(tokens_response).encode("utf-8")}

    def command_acknowledged(self):
        self.target.update_declarations_token(self.declarations_token)


register_command(DeclarativeManagement)
