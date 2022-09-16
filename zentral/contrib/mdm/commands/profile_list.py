from datetime import datetime
import logging
from cryptography import x509
from zentral.contrib.mdm.inventory import commit_update_tree
from zentral.contrib.mdm.models import Channel, Platform
from zentral.utils.certificates import build_cert_tree
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.profile_list")


class ProfileList(Command):
    request_type = "ProfileList"
    allowed_channel = (Channel.Device, Channel.User)
    allowed_platform = (Platform.iOS, Platform.iPadOS, Platform.macOS, Platform.tvOS)
    allowed_in_user_enrollment = True
    reschedule_notnow = True

    def load_kwargs(self):
        self.managed_only = self.db_command.kwargs.get("managed_only", False)
        self.update_inventory = self.db_command.kwargs.get("update_inventory", False)
        self.store_result = not self.update_inventory

    def build_command(self):
        return {"ManagedOnly": self.managed_only}

    def command_acknowledged(self):
        if not self.update_inventory:
            return
        profiles = []
        for item in self.response.get("ProfileList", []):
            profile_tree = {
                "uuid": item["PayloadUUID"],
                "identifier": item.get("PayloadIdentifier"),
                "display_name": item.get("PayloadDisplayName"),
                "description": item.get("PayloadDescription"),
                "organization": item.get("PayloadOrganization"),
                "removal_disallowed": item.get("PayloadRemovalDisallowed"),
                "has_removal_passcode": item.get("HasRemovalPasscode"),
                "verified": item.get("IsManaged"),  # Only present if device is not supervised!
                "encrypted": item.get("IsEncrypted"),
            }
            for payload_item in item.get("PayloadContent", []):
                profile_tree.setdefault("payloads", []).append({
                    "identifier": payload_item.get("PayloadIdentifier"),
                    "type": payload_item.get("PayloadType"),
                    "uuid": payload_item.get("PayloadUUID"),
                })
            signed_object = profile_tree
            for cert_der in item.get("SignerCertificates", []):
                cert = x509.load_der_x509_certificate(cert_der)
                cert_tree = build_cert_tree(cert)
                signed_object["signed_by"] = cert_tree
                signed_object = cert_tree
            signed_object["signed_by"] = None
            if profile_tree not in profiles:
                profiles.append(profile_tree)
        tree = commit_update_tree(self.enrolled_device, {"profiles": profiles})
        if tree is not None:
            self.enrolled_device.profiles_updated_at = datetime.utcnow()
            self.enrolled_device.save()


register_command(ProfileList)
