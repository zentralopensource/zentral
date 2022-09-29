from datetime import datetime
import logging
from zentral.contrib.mdm.inventory import commit_update_tree
from zentral.contrib.mdm.models import Channel, DeviceArtifact, Platform, TargetArtifactStatus
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.installed_application_list")


class InstalledApplicationList(Command):
    request_type = "InstalledApplicationList"
    allowed_channel = (Channel.Device, Channel.User)
    allowed_platform = (Platform.iOS, Platform.iPadOS, Platform.macOS, Platform.tvOS)
    allowed_in_user_enrollment = True
    reschedule_notnow = True

    def load_kwargs(self):
        self.managed_only = self.db_command.kwargs.get("managed_only", False)
        self.retries = self.db_command.kwargs.get("retries", 0)
        self.update_inventory = self.db_command.kwargs.get("update_inventory", False)
        self.apps_to_check = self.db_command.kwargs.get("apps_to_check", [])
        self.store_result = not self.update_inventory and not self.artifact_version

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
        installed = True
        app_key_attrs = list(self.apps_to_check[0].keys())
        for app in self.response.get("InstalledApplicationList", []):
            app_key = {aka: app[aka] for aka in app_key_attrs}
            if app_key not in self.apps_to_check:
                continue
            found = True
            if any(app.get(attr) for attr in ("DownloadWaiting", "DownloadPaused", "Installing")):
                installed = False
            elif any(app.get(attr) for attr in ("DownloadCancelled", "DownloadFailed")):
                error = True
                break
        if found and installed:
            # cleanup
            (DeviceArtifact.objects.filter(enrolled_device=self.enrolled_device,
                                           artifact_version__artifact=self.artifact)
                                   .exclude(artifact_version=self.artifact_version)
                                   .delete())
            # update
            DeviceArtifact.objects.update_or_create(
                enrolled_device=self.enrolled_device,
                artifact_version=self.artifact_version,
                defaults={"status": TargetArtifactStatus.Installed.name}
            )
        elif error:
            # we remove the device artifact, a new install will be triggered
            # TODO evaluate if it is the best option
            # cleanup
            DeviceArtifact.objects.filter(enrolled_device=self.enrolled_device,
                                          artifact_version=self.artifact_version).delete()
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
            self.create_for_device(
                self.enrolled_device,
                self.artifact_version,
                kwargs={"apps_to_check": self.apps_to_check,
                        "retries": self.retries + 1},
                queue=True, delay=first_delay_seconds
            )

    def _update_inventory(self):
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
        tree = commit_update_tree(self.enrolled_device, {"osx_app_instances": osx_app_instances})
        if tree is not None:
            self.enrolled_device.apps_updated_at = datetime.utcnow()
            self.enrolled_device.save()

    def command_acknowledged(self):
        if self.artifact_version and self.apps_to_check:
            self._update_device_artifact()
        elif self.update_inventory:
            self._update_inventory()


register_command(InstalledApplicationList)
