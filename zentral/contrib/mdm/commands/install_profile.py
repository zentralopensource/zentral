import logging
import plistlib
from zentral.utils.payloads import sign_payload
from zentral.contrib.mdm.models import ArtifactOperation, Channel, DeviceArtifact, Platform, UserArtifact
from zentral.contrib.mdm.scep import process_scep_payloads
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.install_profile")


class InstallProfile(Command):
    request_type = "InstallProfile"
    allowed_channel = (Channel.Device, Channel.User)
    allowed_platform = (Platform.iOS, Platform.iPadOS, Platform.macOS, Platform.tvOS)
    allowed_in_user_enrollment = True
    artifact_operation = ArtifactOperation.Installation

    def substitute_variables(self, obj):
        if isinstance(obj, dict):
            obj = {k: self.substitute_variables(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            obj = [self.substitute_variables(i) for i in obj]
        elif isinstance(obj, str):
            for attr in ("serial_number", "udid"):
                obj = obj.replace(f"$ENROLLED_DEVICE.{attr.upper()}",
                                  getattr(self.enrolled_device, attr))
            if self.enrolled_user:
                for attr in ("long_name", "short_name"):
                    obj = obj.replace(f"$ENROLLED_USER.{attr.upper()}",
                                      getattr(self.enrolled_user, attr))
            if self.realm_user:
                for attr in ("username", "device_username",
                             "email_prefix", "email_prefix",  # WARNING order is important
                             "email", "email",
                             "first_name", "last_name", "full_name"):
                    obj = obj.replace(f"$REALM_USER.{attr.upper()}",
                                      getattr(self.realm_user, attr))
            managed_apple_id = getattr(self.enrollment_session, "managed_apple_id", None)
            if managed_apple_id:
                obj = obj.replace("$MANAGED_APPLE_ID.EMAIL", managed_apple_id)
        return obj

    def build_command(self):
        profile = self.artifact_version.profile
        payload = plistlib.loads(profile.source)
        payload = self.substitute_variables(payload)
        process_scep_payloads(payload)
        payload["PayloadIdentifier"] = profile.installed_payload_identifier()
        payload["PayloadUUID"] = profile.installed_payload_uuid()
        # TODO encryption
        return {"Payload": sign_payload(plistlib.dumps(payload))}

    def command_acknowledged(self):
        if self.channel == Channel.Device:
            DeviceArtifact.objects.update_or_create(
                enrolled_device=self.enrolled_device,
                artifact_version__artifact=self.artifact_version.artifact,
                defaults={"artifact_version": self.artifact_version}
            )
        else:
            UserArtifact.objects.update_or_create(
                enrolled_user=self.enrolled_user,
                artifact_version__artifact=self.artifact_version.artifact,
                defaults={"artifact_version": self.artifact_version}
            )


register_command(InstallProfile)
