import logging
from zentral.contrib.mdm.models import Artifact, Channel, TargetArtifact
from zentral.utils.ssl import ensure_bytes
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.install_provisioning_profile")


class InstallProvisioningProfile(Command):
    request_type = "InstallProvisioningProfile"
    artifact_operation = Artifact.Operation.INSTALLATION

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return channel == Channel.DEVICE

    def build_command(self):
        return {"ProvisioningProfile": ensure_bytes(self.artifact_version.provisioning_profile.source)}

    def command_acknowledged(self):
        self.target.update_target_artifact(
            self.artifact_version,
            TargetArtifact.Status.ACKNOWLEDGED,
            unique_install_identifier=self.uuid,
        )

    def command_error(self):
        self.target.update_target_artifact(self.artifact_version, TargetArtifact.Status.FAILED)


register_command(InstallProvisioningProfile)
