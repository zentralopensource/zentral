import logging
from zentral.contrib.mdm.models import Artifact, Channel, Platform, TargetArtifact
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.remove_application")


class RemoveApplication(Command):
    request_type = "RemoveApplication"
    artifact_operation = Artifact.Operation.REMOVAL

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            channel == Channel.DEVICE
            and (
                not enrolled_device.user_enrollment
                or enrolled_device.platform == Platform.IOS
            )
        )

    def build_command(self):
        store_app = self.artifact_version.store_app
        asset = store_app.location_asset.asset
        if not asset.bundle_id:
            raise ValueError(f"Store app {store_app.pk} linked to asset without bundle ID")
        return {"Identifier": asset.bundle_id}

    def command_acknowledged(self):
        self.target.update_target_artifact(
            self.artifact_version,
            TargetArtifact.Status.UNINSTALLED
        )
        # disassociate asset
        # TODO async?
        location_asset = self.artifact_version.store_app.location_asset
        location = location_asset.location
        asset = location_asset.asset
        from zentral.contrib.mdm.apps_books import location_cache
        _, client = location_cache.get(location.mdm_info_id)
        try:
            response = client.post_device_disassociation(self.enrolled_device.serial_number, asset)
        except Exception:
            logger.exception("enrolled device %s asset %s/%s/%s: could not post disassociation",
                             self.enrolled_device.serial_number, location.name, asset.adam_id, asset.pricing_param)
        else:
            if not response.get("eventId"):
                logger.warning("enrolled device %s asset %s/%s/%s: disassociation response without eventId",
                               self.enrolled_device.serial_number, location.name, asset.adam_id, asset.pricing_param)

    def command_error(self):
        # TODO extra infos
        self.target.update_target_artifact(
            self.artifact_version,
            TargetArtifact.Status.REMOVAL_FAILED
        )


register_command(RemoveApplication)
