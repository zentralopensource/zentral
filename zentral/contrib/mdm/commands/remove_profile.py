import logging
from zentral.contrib.mdm.models import Artifact, Channel, Platform, TargetArtifact
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.remove_profile")


class RemoveProfile(Command):
    request_type = "RemoveProfile"
    artifact_operation = Artifact.Operation.REMOVAL

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            (
                channel == Channel.DEVICE
                or enrolled_device.platform in (Platform.IPADOS, Platform.MACOS)
            ) and (
                not enrolled_device.user_enrollment
                or enrolled_device.platform in (Platform.IOS, Platform.MACOS)
            )
        )

    def build_command(self):
        # same identifier for all versions
        return {"Identifier": self.artifact_version.profile.installed_payload_identifier()}

    def command_acknowledged(self):
        self.target.update_target_artifact(
            self.artifact_version,
            TargetArtifact.Status.UNINSTALLED
        )

    def command_error(self):
        self.target.update_target_artifact(
            self.artifact_version,
            TargetArtifact.Status.REMOVAL_FAILED
        )


register_command(RemoveProfile)
