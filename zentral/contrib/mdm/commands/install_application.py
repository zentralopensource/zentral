import logging
from zentral.contrib.mdm.models import ArtifactOperation, Channel, DeviceArtifact, Platform, TargetArtifactStatus
from zentral.contrib.mdm.payloads import substitute_variables
from .base import register_command, Command
from .managed_application_list import ManagedApplicationList


logger = logging.getLogger("zentral.contrib.mdm.commands.install_application")


class InstallApplication(Command):
    request_type = "InstallApplication"
    allowed_channel = Channel.Device  # TODO better?
    allowed_platform = (Platform.iOS, Platform.iPadOS, Platform.macOS, Platform.tvOS)
    allowed_in_user_enrollment = True
    artifact_operation = ArtifactOperation.Installation

    def build_command(self):
        store_app = self.artifact_version.store_app
        cmd = {
            "iTunesStoreID": int(store_app.asset.adam_id),
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
            identifier = self.artifact_version.store_app.asset.bundle_id
        if identifier:
            DeviceArtifact.objects.update_or_create(
                enrolled_device=self.enrolled_device,
                artifact_version=self.artifact_version,
                defaults={"status": TargetArtifactStatus.AwaitingConfirmation.name}
            )
            # queue an installed application list command
            first_delay_seconds = 15  # TODO hardcoded
            ManagedApplicationList.create_for_device(
                self.enrolled_device,
                self.artifact_version,
                kwargs={"identifiers": [identifier]},  # TODO version will not be checked!
                queue=True, delay=first_delay_seconds
            )
        else:
            # cleanup
            (DeviceArtifact.objects.filter(enrolled_device=self.enrolled_device,
                                           artifact_version__artifact=self.artifact)
                                   .exclude(artifact_version=self.artifact_version)
                                   .delete())
            # update or create new record
            DeviceArtifact.objects.update_or_create(
                enrolled_device=self.enrolled_device,
                artifact_version=self.artifact_version,
                defaults={"status": TargetArtifactStatus.Acknowledged.name}
            )


register_command(InstallApplication)
