import logging
from zentral.contrib.mdm.models import ArtifactOperation, Channel, DeviceArtifact, Platform, UserArtifact
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.install_enterprise_application")


class InstallEnterpriseApplication(Command):
    request_type = "InstallEnterpriseApplication"
    allowed_channel = Channel.Device
    allowed_platform = Platform.macOS
    allowed_in_user_enrollment = True
    artifact_operation = ArtifactOperation.Installation

    def build_command(self):
        # TODO manage options
        # see https://developer.apple.com/documentation/devicemanagement/installenterpriseapplicationcommand/command
        return {
            "InstallAsManaged": True,
            "ManagementFlags": 1,
            "Manifest": self.artifact_version.enterprise_app.manifest
        }

    def command_acknowledged(self):
        if self.channel == Channel.Device:
            DeviceArtifact.objects.update_or_create(
                enrolled_device=self.enrolled_device,
                artifact_version__artifact=self.artifact,
                defaults={"artifact_version": self.artifact_version}
            )
        else:
            UserArtifact.objects.update_or_create(
                enrolled_user=self.enrolled_user,
                artifact_version__artifact=self.artifact,
                defaults={"artifact_version": self.artifact_version}
            )


register_command(InstallEnterpriseApplication)
