from datetime import datetime
import logging
from cryptography import x509
from zentral.contrib.mdm.inventory import commit_update_tree
from zentral.contrib.mdm.models import Channel, Platform
from zentral.utils.certificates import build_cert_tree
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.certificate_list")


class CertificateList(Command):
    request_type = "CertificateList"
    reschedule_notnow = True

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            channel == Channel.Device
            and (
                not enrolled_device.user_enrollment
                or enrolled_device.platform in (Platform.iOS.name, Platform.macOS.name)
            )
        )

    def load_kwargs(self):
        self.managed_only = self.db_command.kwargs.get("managed_only", False)
        self.update_inventory = self.db_command.kwargs.get("update_inventory", False)
        self.store_result = not self.update_inventory

    def build_command(self):
        return {"ManagedOnly": self.managed_only}

    def command_acknowledged(self):
        if not self.update_inventory:
            return
        certificates = []
        for item in self.response.get("CertificateList", []):
            if not item.get("IsIdentity", False):
                continue
            cert = x509.load_der_x509_certificate(item["Data"])
            cert_tree = build_cert_tree(cert)
            if cert_tree not in certificates:
                certificates.append(cert_tree)
        tree = commit_update_tree(self.enrolled_device, {"certificates": certificates})
        if tree is not None:
            self.enrolled_device.certificates_updated_at = datetime.utcnow()
            self.enrolled_device.save()


register_command(CertificateList)
