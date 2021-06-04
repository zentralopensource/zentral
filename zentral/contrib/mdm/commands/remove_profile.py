import logging
from zentral.contrib.mdm.models import ArtifactOperation, Channel, DeviceArtifact, Platform, UserArtifact
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.remove_profile")


class RemoveProfile(Command):
    request_type = "RemoveProfile"
    allowed_channel = (Channel.Device, Channel.User)
    allowed_platform = (Platform.iOS, Platform.iPadOS, Platform.macOS, Platform.tvOS)
    allowed_in_user_enrollment = True
    artifact_operation = ArtifactOperation.Removal

    def build_command(self):
        # same identifier for all versions
        return {"Identifier": self.artifact_version.profile.installed_payload_identifier()}

    def command_acknowledged(self):
        if self.channel == Channel.Device:
            DeviceArtifact.objects.filter(enrolled_device=self.enrolled_device,
                                          artifact_version__artifact=self.artifact).delete()
        else:
            UserArtifact.objects.filter(enrolled_user=self.enrolled_user,
                                        artifact_version__artifact=self.artifact).delete()


register_command(RemoveProfile)
