import logging
from zentral.contrib.mdm.models import Channel, Platform, TargetArtifact
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.managed_application_list")


class ManagedApplicationList(Command):
    request_type = "ManagedApplicationList"
    reschedule_notnow = True

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            (
                channel == Channel.DEVICE
                or enrolled_device.platform == Platform.MACOS
            ) and (
                not enrolled_device.user_enrollment
                or enrolled_device.platform in (Platform.IOS, Platform.IPADOS, Platform.MACOS)
            )
        )

    def load_kwargs(self):
        self.identifiers = self.db_command.kwargs.get("identifiers", [])
        self.retries = self.db_command.kwargs.get("retries", 0)
        self.store_result = not self.identifiers

    def build_command(self):
        command = {}
        if self.identifiers:
            command["Identifiers"] = self.identifiers
        return command

    def _update_device_artifact(self):
        found = True
        retry = True
        extra_info = {}
        ta_status = None
        application_list = self.response.get("ManagedApplicationList", {})  # it is a dict!!!
        for identifier in self.identifiers:
            app = application_list.get(identifier)
            if not app:
                found = False
                continue
            status = app.get("Status")
            extra_info["status"] = status
            if status in ("Managed", "UserInstalledApp"):
                ta_status = TargetArtifact.Status.INSTALLED
                retry = False
            elif status in ("Failed", "ManagementRejected", "UserRejected", "UpdateRejected"):
                ta_status = TargetArtifact.Status.FAILED
                retry = False
            elif status == "ManagedButUninstalled":
                ta_status = TargetArtifact.Status.UNINSTALLED
                retry = False
            else:
                ta_status = TargetArtifact.Status.AWAITING_CONFIRMATION

        if ta_status:
            self.target.update_target_artifact(
                self.artifact_version,
                ta_status,
                extra_info=extra_info,
                unique_install_identifier=self.uuid,
            )
        if not found:
            logger.warning("Artifact version %s was not found on device %s.",
                           self.artifact_version.pk, self.enrolled_device.serial_number)
        if retry:
            if self.retries >= 10:  # TODO hardcoded
                logger.warning("Stop rescheduling %s command on device %s for artifact version %s.",
                               self.request_type,
                               self.enrolled_device.serial_number,
                               self.artifact_version.pk)
            else:
                # queue a new managed application list command
                delay_seconds = 15  # TODO hardcoded
                self.create_for_target(
                    self.target,
                    self.artifact_version,
                    kwargs={"identifiers": self.identifiers,
                            "retries": self.retries + 1},
                    queue=True, delay=delay_seconds
                )

    def command_acknowledged(self):
        if self.artifact_version and self.identifiers:
            self._update_device_artifact()


register_command(ManagedApplicationList)
