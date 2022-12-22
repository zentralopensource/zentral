import logging
from zentral.contrib.mdm.models import ArtifactOperation, Channel, DeviceArtifact, Platform
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.remove_application")


class RemoveApplication(Command):
    request_type = "RemoveApplication"
    artifact_operation = ArtifactOperation.Removal

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            channel == Channel.Device
            and (
                not enrolled_device.user_enrollment
                or enrolled_device.platform == Platform.iOS.name
            )
        )

    def build_command(self):
        store_app = self.artifact_version.store_app
        if not store_app.bundle_id:
            raise ValueError(f"Store app {store_app.pk} without bundle ID")
        return {"Identifier": store_app.bundle_id}

    def command_acknowledged(self):
        DeviceArtifact.objects.filter(enrolled_device=self.enrolled_device,
                                      artifact_version__artifact=self.artifact).delete()


register_command(RemoveApplication)
