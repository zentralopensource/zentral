from datetime import datetime, timedelta
import logging
import plistlib
import uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, load_der_private_key
from cryptography.x509.oid import NameOID
from zentral.contrib.mdm.models import Channel, FileVaultConfig, Platform
from zentral.utils.payloads import sign_payload
from .base import register_command, Command
from .security_info import SecurityInfo


logger = logging.getLogger("zentral.contrib.mdm.commands.setup_filevault")


def get_escrow_key(enrolled_device):
    raw_escrow_key = enrolled_device.get_filevault_escrow_key()
    if not raw_escrow_key:
        escrow_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        raw_escrow_key = escrow_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        enrolled_device.set_filevault_escrow_key(raw_escrow_key)
        enrolled_device.save()
    else:
        escrow_key = load_der_private_key(raw_escrow_key, password=None)
    return escrow_key


def get_escrow_key_certificate_der_bytes(enrolled_device):
    escrow_key = get_escrow_key(enrolled_device)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Zentral FileVault PRK escrow key')
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Zentral')
    ]))
    now = datetime.utcnow()
    builder = builder.not_valid_before(now - timedelta(days=1))
    builder = builder.not_valid_after(now + timedelta(days=20 * 366))  # ~20 years
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(escrow_key.public_key())
    certificate = builder.sign(
        private_key=escrow_key, algorithm=hashes.SHA256()
    )
    return certificate.public_bytes(Encoding.DER)


def build_payload(enrolled_device):
    filevault_config = enrolled_device.blueprint.filevault_config
    cert_payload_uuid = str(uuid.uuid4())
    config = {
        "PayloadContent": [
            # FDE Configuration
            {"Enable": "On",
             "ShowRecoveryKey": filevault_config.show_recovery_key,
             "UseRecoveryKey": True,
             "PayloadType": "com.apple.MCX.FileVault2",
             "PayloadIdentifier": "com.zentral.mdm.fv.configuration",
             "PayloadUUID": str(uuid.uuid4()),
             "PayloadVersion": 1},
            # FDE Options
            {"DestroyFVKeyOnStandby": filevault_config.destroy_key_on_standby,
             "dontAllowFDEDisable": True,
             "dontAllowFDEEnable": False,
             "PayloadType": "com.apple.MCX",
             "PayloadIdentifier": "com.zentral.mdm.fv.options",
             "PayloadUUID": str(uuid.uuid4()),
             "PayloadVersion": 1},
            # FDE recovery key escrow encryption certificate
            {"PayloadContent": get_escrow_key_certificate_der_bytes(enrolled_device),
             "PayloadType": "com.apple.security.pkcs1",
             "PayloadIdentifier": "com.zentral.mdm.fv.certificate",
             "PayloadUUID": cert_payload_uuid,
             "PayloadVersion": 1},
            # FDE recovery key escrow
            {"Location": filevault_config.escrow_location_display_name,
             "EncryptCertPayloadUUID": cert_payload_uuid,
             "PayloadType": "com.apple.security.FDERecoveryKeyEscrow",
             "PayloadIdentifier": "com.zentral.mdm.fv.escrow",
             "PayloadUUID": str(uuid.uuid4()),
             "PayloadVersion": 1},
        ],
        "PayloadDisplayName": "Zentral - FileVault configuration",
        "PayloadType": "Configuration",
        "PayloadIdentifier": "com.zentral.mdm.fv",
        "PayloadUUID": str(filevault_config.uuid),
        "PayloadVersion": 1,
    }
    fv_config = config["PayloadContent"][0]
    if enrolled_device.awaiting_configuration and enrolled_device.comparable_os_version >= (14,):
        fv_config.update({
            "ForceEnableInSetupAssistant": True,
            "Defer": True,  # macOS 14.4 workaround TODO: re-evaluate later
        })
    else:
        fv_config.update({
            "Defer": True,
            "DeferDontAskAtUserLogout": filevault_config.at_login_only,
            "DeferForceAtUserLoginMaxBypassAttempts": filevault_config.bypass_attempts,
        })
    # TODO encryption
    return sign_payload(plistlib.dumps(config))


class SetupFileVault(Command):
    request_type = "InstallProfile"
    db_name = "SetupFileVault"
    reschedule_notnow = True

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        if (
            channel == Channel.DEVICE
            and enrolled_device.platform == Platform.MACOS
            and enrolled_device.user_approved_enrollment
            and not enrolled_device.user_enrollment
        ):
            blueprint = enrolled_device.blueprint
            if not blueprint:
                return False
            filevault_config = blueprint.filevault_config
            if not filevault_config:
                return False
            return True
        else:
            return False

    @classmethod
    def create_for_target(cls, target):
        filevault_config = target.enrolled_device.blueprint.filevault_config
        return super().create_for_target(
            target,
            kwargs={"filevault_config_pk": filevault_config.pk,
                    "filevault_config_uuid": str(filevault_config.uuid)}
        )

    def load_kwargs(self):
        kwargs = self.db_command.kwargs
        try:
            self.filevault_config = FileVaultConfig.objects.get(pk=kwargs["filevault_config_pk"])
        except FileVaultConfig.DoesNotExist:
            self.filevault_config = None
        self.filevault_config_uuid = uuid.UUID(kwargs["filevault_config_uuid"])

    def build_command(self):
        return {"Payload": build_payload(self.enrolled_device)}

    def command_acknowledged(self):
        self.enrolled_device.filevault_config_uuid = self.filevault_config_uuid
        self.enrolled_device.save()
        # schedule a delayed SecurityInfo command to fetch the PRK
        filevault_prk_escrow_delay = 10 * 60  # 10 min. TODO hardcoded
        SecurityInfo.create_for_target(
            self.target,
            queue=True, delay=filevault_prk_escrow_delay
        )


register_command(SetupFileVault)
