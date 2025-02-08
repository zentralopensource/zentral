import logging
from zentral.contrib.mdm.models import Artifact, Channel, Platform, TargetArtifact
from zentral.contrib.mdm.payloads import substitute_variables
from .base import register_command, Command
from .managed_application_list import ManagedApplicationList


logger = logging.getLogger("zentral.contrib.mdm.commands.install_application")


class InstallApplication(Command):
    request_type = "InstallApplication"
    artifact_operation = Artifact.Operation.INSTALLATION

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

    def build_command(self):
        store_app = self.artifact_version.store_app
        cmd = {
            "iTunesStoreID": int(store_app.location_asset.asset.adam_id),
            "InstallAsManaged": True,
            "Options": {"PurchaseMethod": 1},
            "ManagementFlags": store_app.get_management_flags(),
            "Attributes": {"Removable": store_app.removable},
        }
        # change management
        if self.enrolled_device.user_enrollment is not None and not self.enrolled_device.user_enrollment:
            # TODO verify
            cmd["ChangeManagementState"] = "Managed"
        # config
        configuration = store_app.get_configuration()
        if configuration:
            cmd["Configuration"] = substitute_variables(configuration, self.enrollment_session, self.enrolled_user)
        # attributes
        for attrs_k, sa_k in (("AssociatedDomains", "associated_domains"),
                              ("AssociatedDomainsEnableDirectDownloads", "associated_domains_enable_direct_downloads"),
                              ("VPNUUID", "vpn_uuid"),
                              ("ContentFilterUUID", "content_filter_uuid"),
                              ("DNSProxyUUID", "dns_proxy_uuid")):
            sa_v = getattr(store_app, sa_k)
            if sa_v:
                cmd["Attributes"][attrs_k] = sa_v
        return cmd

    def command_acknowledged(self):
        identifier = self.response.get("Identifier")
        if not identifier:
            identifier = self.artifact_version.store_app.location_asset.asset.bundle_id
        if identifier:
            self.target.update_target_artifact(
                self.artifact_version,
                TargetArtifact.Status.AWAITING_CONFIRMATION
            )
            # queue a managed application list command
            first_delay_seconds = 15  # TODO hardcoded
            ManagedApplicationList.create_for_target(
                self.target,
                self.artifact_version,
                kwargs={"identifiers": [identifier]},  # TODO version will not be checked!
                queue=True, delay=first_delay_seconds
            )
        else:
            self.target.update_target_artifact(
                self.artifact_version,
                TargetArtifact.Status.ACKNOWLEDGED,
                unique_install_identifier=self.uuid,
            )


register_command(InstallApplication)
