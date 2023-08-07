from datetime import datetime
import logging
from cryptography.hazmat.primitives.serialization import load_der_private_key
from django.db import transaction
from zentral.contrib.mdm.crypto import decrypt_cms_payload
from zentral.contrib.mdm.events import post_filevault_prk_updated_event
from zentral.contrib.mdm.models import Channel, Platform
from zentral.utils.json import prepare_loaded_plist
from .base import register_command, Command, CommandBaseForm


logger = logging.getLogger("zentral.contrib.mdm.commands.security_info")


class SecurityInfoForm(CommandBaseForm):
    pass


class SecurityInfo(Command):
    request_type = "SecurityInfo"
    display_name = "Security info"
    reschedule_notnow = True
    form_class = SecurityInfoForm

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            channel == Channel.DEVICE
            and (
                not enrolled_device.user_enrollment
                or enrolled_device.platform in (Platform.IOS, Platform.MACOS)
            )
        )

    def command_acknowledged(self):
        security_info = self.response.get("SecurityInfo")
        if not security_info:
            logger.warning("Enrolled device %s: absent or empty SecurityInfo.",
                           self.enrolled_device.udid)
            return

        # FileVault PRK
        if self.enrolled_device.filevault_escrow_key:
            prk_cms = security_info.pop("FDE_PersonalRecoveryKeyCMS", None)
            if prk_cms:
                escrow_key = load_der_private_key(self.enrolled_device.get_filevault_escrow_key(), password=None)
                try:
                    prk = decrypt_cms_payload(prk_cms, escrow_key, der=True).decode("utf-8")
                except Exception:
                    logger.exception("Could not decrypt enrolled device %s FileVault PRK",
                                     self.enrolled_device.serial_number)
                else:
                    if prk and prk != self.enrolled_device.get_filevault_prk():
                        self.enrolled_device.set_filevault_prk(prk)
                        transaction.on_commit(lambda: post_filevault_prk_updated_event(self))

        self.enrolled_device.security_info = prepare_loaded_plist(security_info)
        self.enrolled_device.security_info_updated_at = datetime.utcnow()
        # management status
        management_status = security_info.get("ManagementStatus")
        if management_status:
            for attr, status_attr in (("dep_enrollment", "EnrolledViaDEP"),
                                      ("activation_lock_manageable", "IsActivationLockManageable"),
                                      ("user_enrollment", "IsUserEnrollment"),
                                      ("user_approved_enrollment", "UserApprovedEnrollment")):
                val = management_status.get(status_attr)
                if isinstance(val, bool):
                    setattr(self.enrolled_device, attr, val)
        # bootstrap token
        for attr, info_attr in (("bootstrap_token_allowed_for_authentication",
                                 "BootstrapTokenAllowedForAuthentication"),
                                ("bootstrap_token_required_for_software_update",
                                 "BootstrapTokenRequiredForSoftwareUpdate"),
                                ("bootstrap_token_required_for_kext_approval",
                                 "BootstrapTokenRequiredForKernelExtensionApproval")):
            val = security_info.get(info_attr)
            if isinstance(val, str):
                if val == "allowed":
                    val = True
                elif val == "disallowed":
                    val = False
            if not isinstance(val, bool):
                val = None
            setattr(self.enrolled_device, attr, val)
        self.enrolled_device.save()


register_command(SecurityInfo)
