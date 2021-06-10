import logging
from django.db import transaction
from zentral.contrib.mdm.models import Channel, DeviceArtifact, Platform, TargetArtifactStatus
from zentral.contrib.mdm.tasks import send_enrolled_device_notification
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.installed_application_list")


class InstalledApplicationList(Command):
    request_type = "InstalledApplicationList"
    allowed_channel = (Channel.Device, Channel.User)
    allowed_platform = (Platform.iOS, Platform.iPadOS, Platform.macOS, Platform.tvOS)
    allowed_in_user_enrollment = True

    def load_kwargs(self):
        self.retries = self.db_command.kwargs.get("retries", 0)

    def build_command(self):
        command = {"ManagedAppsOnly": False,
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
                             "IsValidated",
                             "Name",
                             "ShortVersion",
                             "Version"]}
        if self.artifact_version:
            identifiers = [bundle["id"] for bundle in self.artifact_version.enterprise_app.bundles]
            if identifiers:
                command["Identifiers"] = identifiers
            else:
                logger.error("Artifact version %s has no bundles.", self.artifact_version.pk)
        return command

    def command_acknowledged(self):
        if not self.artifact_version:
            # TODO save all the apps?
            return
        else:
            # this command was sent to check on an install
            # TODO we do not use the version, because it seems to be reported differently
            # maybe because we get the wrong one when we analyse the Distribution
            keys = set((bundle["id"], bundle["version_str"])
                       for bundle in self.artifact_version.enterprise_app.bundles)
            if not keys:
                logger.error("Artifact version %s has no bundles.", self.artifact_version.pk)
                return
            found = False
            error = False
            installed = True
            for app in self.response.get("InstalledApplicationList", []):
                key = (app["Identifier"], app["ShortVersion"])
                if key not in keys:
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
                    kwargs={"retries": self.retries + 1},
                    queue=True, delay=first_delay_seconds
                )
                transaction.on_commit(lambda: send_enrolled_device_notification(self.enrolled_device,
                                                                                delay=first_delay_seconds))


register_command(InstalledApplicationList)
