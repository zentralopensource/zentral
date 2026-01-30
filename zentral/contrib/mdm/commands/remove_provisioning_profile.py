import logging
from zentral.contrib.mdm.models import Artifact, Channel, TargetArtifact
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.remove_provisioning_profile")


class RemoveProvisioningProfile(Command):
    request_type = "RemoveProvisioningProfile"
    artifact_operation = Artifact.Operation.REMOVAL

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return channel == Channel.DEVICE

    def build_command(self):
        return {"UUID": str(self.artifact_version.provisioning_profile.uuid)}

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


register_command(RemoveProvisioningProfile)
