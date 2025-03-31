import logging
from zentral.contrib.mdm.inventory import update_inventory_tree
from zentral.contrib.mdm.models import Channel, Platform, TargetArtifact
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.installed_application_list")


class InstalledApplicationList(Command):
    request_type = "InstalledApplicationList"
    reschedule_notnow = True
    store_result = True

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            (
                channel == Channel.DEVICE
                or enrolled_device.platform == Platform.MACOS
            ) and (
                not enrolled_device.user_enrollment
                or enrolled_device.platform in (Platform.IOS, Platform.IPADOS)
            )
        )

    def load_kwargs(self):
        self.managed_only = self.db_command.kwargs.get("managed_only", False)
        self.retries = self.db_command.kwargs.get("retries", 0)
        self.update_inventory = self.db_command.kwargs.get("update_inventory", False)
        self.apps_to_check = self.db_command.kwargs.get("apps_to_check", [])

    def build_command(self):
        command = {"ManagedAppsOnly": self.managed_only,
                   "Items": ["AdHocCodeSigned",
                             "AppStoreVendable",
                             "BetaApp",
                             "BundleSize",
                             "DeviceBasedVPP",
                             "DynamicSize",
                             "ExternalVersionIdentifier",
                             "HasUpdateAvailable",
                             "Identifier",
                             "Installing",
                             "IsAppClip",
                             "IsValidated",
                             "Name",
                             "ShortVersion",
                             "Version"]}
        if self.apps_to_check:
            command["Identifiers"] = [app["Identifier"] for app in self.apps_to_check]
        return command

    def _update_device_artifact(self):
        # this command was sent to check on an install
        found = False
        error = False
        extra_info = {}
        installed = True
        app_key_attrs = list(self.apps_to_check[0].keys())
        for app in self.response.get("InstalledApplicationList", []):
            app_key = {aka: app[aka] for aka in app_key_attrs}
            if app_key not in self.apps_to_check:
                continue
            found = True
            for attr in ("DownloadCancelled", "DownloadFailed",
                         "DownloadPaused", "DownloadWaiting",
                         "Installing"):
                extra_info[attr] = app.get(attr)
            if any(app.get(attr) for attr in ("DownloadWaiting", "DownloadPaused", "Installing")):
                installed = False
            if any(app.get(attr) for attr in ("DownloadCancelled", "DownloadFailed")):
                error = True
        if not error and found and installed:
            self.target.update_target_artifact(
                self.artifact_version,
                TargetArtifact.Status.INSTALLED,
                unique_install_identifier=self.uuid,
            )
        elif error:
            self.target.update_target_artifact(
                self.artifact_version,
                TargetArtifact.Status.FAILED,
                extra_info=extra_info
            )
        else:
            if not found:
                logger.warning("Artifact version %s was not found.", self.artifact_version.pk)
            if self.retries >= 10:  # TODO hardcoded
                logger.warning("Stop rescheduling %s command for artifact version %s",
                               self.request_type,
                               self.artifact_version.pk)
                return
            # queue a new installed application list command
            first_delay_seconds = 15  # TODO hardcoded
            self.create_for_target(
                self.target,
                self.artifact_version,
                kwargs={"apps_to_check": self.apps_to_check,
                        "retries": self.retries + 1},
                queue=True, delay=first_delay_seconds * (self.retries + 1)
            )

    def get_inventory_partial_tree(self):
        osx_app_instances = []
        for item in self.response.get("InstalledApplicationList", []):
            if any(item.get(k, False) for k in ("DownloadCancelled",
                                                "DownloadFailed",
                                                "DownloadPaused",
                                                "DownloadWaiting",
                                                "Installing")):
                continue
            osx_app_instance_tree = {
                "app": {
                    "bundle_id": item.get("Identifier") or None,
                    "bundle_name": item.get("Name"),
                    "bundle_version": item.get("Version"),
                    "bundle_version_str": item.get("ShortVersion")
                }
            }
            if osx_app_instance_tree not in osx_app_instances:
                osx_app_instances.append(osx_app_instance_tree)
        return {"osx_app_instances": osx_app_instances}

    def command_acknowledged(self):
        if self.artifact_version and self.apps_to_check:
            self._update_device_artifact()
        elif self.update_inventory:
            update_inventory_tree(self)


register_command(InstalledApplicationList)
