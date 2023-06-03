import logging
from django.urls import reverse
from zentral.conf import settings
from zentral.contrib.mdm.models import Artifact, Channel, Platform, TargetArtifact
from zentral.contrib.mdm.payloads import substitute_variables
from .base import register_command, Command
from .installed_application_list import InstalledApplicationList


logger = logging.getLogger("zentral.contrib.mdm.commands.install_enterprise_application")


class InstallEnterpriseApplication(Command):
    request_type = "InstallEnterpriseApplication"
    artifact_operation = Artifact.Operation.INSTALLATION

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return channel == Channel.DEVICE and enrolled_device.platform == Platform.MACOS

    def build_command(self):
        enterprise_app = self.artifact_version.enterprise_app
        manifest = enterprise_app.manifest
        manifest["items"][0]["assets"][0]["url"] = "https://{}{}".format(settings["api"]["fqdn"],
                                                                         reverse("mdm_public:enterprise_app_download",
                                                                                 args=(self.db_command.uuid,)))
        cmd = {"Manifest": manifest}
        configuration = enterprise_app.get_configuration()
        if configuration:
            cmd["Configuration"] = substitute_variables(configuration, self.enrollment_session, self.enrolled_user)
        if enterprise_app.ios_app:
            cmd["iOSApp"] = True
        if self.enrolled_device.comparable_os_version >= (11,):
            if enterprise_app.install_as_managed:
                # App must install to /Applications
                # App must contain a single app
                cmd["InstallAsManaged"] = True
                cmd["ChangeManagementState"] = "Managed"
                cmd["ManagementFlags"] = 1 if enterprise_app.remove_on_unenroll else 0
            else:
                cmd["InstallAsManaged"] = False
        return cmd

    def command_acknowledged(self):
        apps_to_check = None
        if self.artifact_version.enterprise_app.bundles:
            # TODO we do not use the version, because it seems to be reported differently
            # maybe because we get the wrong one when we analyse the Distribution
            apps_to_check = [
                {"Identifier": bundle["id"], "ShortVersion": bundle["version_str"]}
                for bundle in self.artifact_version.enterprise_app.bundles
            ]
        if apps_to_check:
            self.target.update_target_artifact(
                self.artifact_version,
                TargetArtifact.Status.AWAITING_CONFIRMATION
            )
            # queue an installed application list command
            first_delay_seconds = 15  # TODO hardcoded
            InstalledApplicationList.create_for_target(
                self.target,
                self.artifact_version,
                kwargs={"apps_to_check": apps_to_check},
                queue=True, delay=first_delay_seconds
            )
        else:
            self.target.update_target_artifact(
                self.artifact_version,
                TargetArtifact.Status.ACKNOWLEDGED,
                allow_reinstall=True,
            )


register_command(InstallEnterpriseApplication)
