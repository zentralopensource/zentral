import logging
from cryptography import x509
from zentral.contrib.mdm.inventory import update_inventory_tree
from zentral.contrib.mdm.models import Channel, Platform
from zentral.utils.certificates import build_cert_tree
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.certificate_list")


class CertificateList(Command):
    request_type = "CertificateList"
    reschedule_notnow = True
    store_result = True

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            channel == Channel.DEVICE
            and (
                not enrolled_device.user_enrollment
                or enrolled_device.platform in (Platform.IOS, Platform.MACOS)
            )
        )

    def load_kwargs(self):
        self.managed_only = self.db_command.kwargs.get("managed_only", False)
        self.update_inventory = self.db_command.kwargs.get("update_inventory", False)

    def build_command(self):
        return {"ManagedOnly": self.managed_only}

    def get_inventory_partial_tree(self):
        certificates = []
        for item in self.response.get("CertificateList", []):
            if not item.get("IsIdentity", False):
                continue
            cert = x509.load_der_x509_certificate(item["Data"])
            cert_tree = build_cert_tree(cert)
            if cert_tree not in certificates:
                certificates.append(cert_tree)
        return {"certificates": certificates}

    def command_acknowledged(self):
        if self.update_inventory:
            update_inventory_tree(self)


register_command(CertificateList)
