import logging
import plistlib
from zentral.utils.payloads import sign_payload
from zentral.contrib.mdm.models import Artifact, Channel, Platform, SCEPConfig, TargetArtifact
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
    artifact_operation = Artifact.Operation.INSTALLATION

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            (
                channel == Channel.DEVICE
                or enrolled_device.platform in (Platform.IPADOS, Platform.MACOS)
            ) and (
                not enrolled_device.user_enrollment
                or enrolled_device.platform in (Platform.IOS, Platform.IPADOS, Platform.MACOS)
            )
        )

    def build_command(self):
        return {"Payload": build_payload(self.artifact_version.profile, self.enrollment_session, self.enrolled_user)}

    def command_acknowledged(self):
        self.target.update_target_artifact(
            self.artifact_version,
            TargetArtifact.Status.ACKNOWLEDGED,
            allow_reinstall=True
        )

    def command_error(self):
        self.target.update_target_artifact(self.artifact_version, TargetArtifact.Status.FAILED)


register_command(InstallProfile)
