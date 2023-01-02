import logging
import plistlib
from zentral.utils.payloads import sign_payload
from zentral.contrib.mdm.models import ArtifactOperation, Channel, DeviceArtifact, Platform, SCEPConfig, UserArtifact
from zentral.contrib.mdm.payloads import substitute_variables
from zentral.contrib.mdm.scep import update_scep_payload
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.install_profile")


def process_scep_payloads(profile_payload):
    for payload in profile_payload.get("PayloadContent", []):
        if payload.get("PayloadType") == "com.apple.security.scep":
            # does the payload have a PayloadContent?
            payload_content = payload.get("PayloadContent")
            if not payload_content:
                continue
            # does the PayloadContent have a name?
            name = payload_content.get("Name")
            if not name:
                # nothing to do
                continue
            # do we have a matching config in the DB?
            try:
                scep_config = SCEPConfig.objects.get(name=name)
            except SCEPConfig.DoesNotExist:
                # nothing to do
                continue
            update_scep_payload(payload_content, scep_config)


def build_payload(profile, enrollment_session, enrolled_user=None):
    payload = plistlib.loads(profile.source)
    payload = substitute_variables(payload, enrollment_session, enrolled_user)
    process_scep_payloads(payload)
    payload["PayloadIdentifier"] = profile.installed_payload_identifier()
    payload["PayloadUUID"] = profile.installed_payload_uuid()
    # TODO encryption
    return sign_payload(plistlib.dumps(payload))


class InstallProfile(Command):
    request_type = "InstallProfile"
    artifact_operation = ArtifactOperation.Installation

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            (
                channel == Channel.Device
                or enrolled_device.platform in (Platform.iPadOS.name, Platform.macOS.name)
            ) and (
                not enrolled_device.user_enrollment
                or enrolled_device.platform in (Platform.iOS.name, Platform.macOS.name)
            )
        )

    def build_command(self):
        return {"Payload": build_payload(self.artifact_version.profile, self.enrollment_session, self.enrolled_user)}

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
