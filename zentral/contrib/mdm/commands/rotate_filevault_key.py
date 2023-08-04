from datetime import datetime, timedelta
import logging
from uuid import uuid4
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, load_der_private_key
from cryptography.x509.oid import NameOID
from django.db import transaction
from zentral.contrib.mdm.crypto import decrypt_cms_payload
from zentral.contrib.mdm.events import post_filevault_prk_updated_event
from zentral.contrib.mdm.models import Channel, Platform
from zentral.core.secret_engines import decrypt, encrypt
from .base import register_command, Command, CommandBaseForm


logger = logging.getLogger("zentral.contrib.mdm.commands.rotate_filevault_key")


class RotateFileVaultKeyForm(CommandBaseForm):
    pass


def get_encryption_key_der_bytes():
    privkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return privkey.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())


def get_encryption_cert_der_bytes(encryption_key):
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Zentral FileVault PRK encryption key')
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Zentral')
    ]))
    now = datetime.utcnow()
    builder = builder.not_valid_before(now - timedelta(days=1))
    builder = builder.not_valid_after(now + timedelta(days=1))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(encryption_key.public_key())
    certificate = builder.sign(
        private_key=encryption_key, algorithm=hashes.SHA256()
    )
    return certificate.public_bytes(Encoding.DER)


class RotateFileVaultKey(Command):
    request_type = "RotateFileVaultKey"
    display_name = "Rotate FileVault key"
    form_class = RotateFileVaultKeyForm

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            channel == Channel.DEVICE
            and enrolled_device.platform == Platform.MACOS
            and not enrolled_device.user_enrollment
            and enrolled_device.filevault_prk
        )

    @classmethod
    def create_for_target(
        cls,
        target,
        artifact_version=None,
        kwargs=None,
        queue=False, delay=0,
        uuid=None
    ):
        if uuid is None:
            uuid = uuid4()
        return super().create_for_target(
            target,
            kwargs={"encryption_key": encrypt(get_encryption_key_der_bytes(),
                                              model="mdm.devicecommand",
                                              field="encryption_key",
                                              uuid=str(uuid))},
            queue=queue, delay=delay,
            uuid=uuid,
        )

    def load_encryption_key(self):
        encrypted_encryption_key = self.db_command.kwargs["encryption_key"]
        encryption_key = decrypt(encrypted_encryption_key,
                                 model="mdm.devicecommand",
                                 field="encryption_key",
                                 uuid=str(self.uuid))
        return load_der_private_key(encryption_key, password=None)

    def build_command(self):
        return {
            "FileVaultUnlock": {"Password": self.enrolled_device.get_filevault_prk()},
            "KeyType": "personal",
            "ReplyEncryptionCertificate": get_encryption_cert_der_bytes(self.load_encryption_key()),
        }

    def command_acknowledged(self):
        prk_cms = self.response.get("RotateResult", {}).get("EncryptedNewRecoveryKey")
        if prk_cms:
            encryption_key = self.load_encryption_key()
            try:
                prk = decrypt_cms_payload(prk_cms, encryption_key, der=True).decode("utf-8")
            except Exception:
                logger.exception("Could not decrypt enrolled device %s new FileVault PRK",
                                 self.enrolled_device.serial_number)
            else:
                if prk and prk != self.enrolled_device.get_filevault_prk():
                    self.enrolled_device.set_filevault_prk(prk)
                    self.enrolled_device.save()
                    transaction.on_commit(lambda: post_filevault_prk_updated_event(self))


register_command(RotateFileVaultKey)
