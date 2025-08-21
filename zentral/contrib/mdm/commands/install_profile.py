import logging
import plistlib
from zentral.utils.payloads import sign_payload
from zentral.contrib.mdm.models import Artifact, Channel, Platform, SCEPIssuer, TargetArtifact
from zentral.contrib.mdm.payloads import substitute_variables
from zentral.contrib.mdm.cert_issuer_backends import get_cached_cert_issuer_backend
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.install_profile")


def process_scep_payloads(profile_payload, enrollment_session, enrolled_user):
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
                scep_issuer = SCEPIssuer.objects.get(name=name)
            except SCEPIssuer.DoesNotExist:
                # nothing to do
                continue
            get_cached_cert_issuer_backend(scep_issuer).update_scep_payload(
                payload_content,
                enrollment_session,
                enrolled_user,
            )


def build_payload(profile, enrollment_session, enrolled_user=None):
    payload = plistlib.loads(profile.source)
    payload = substitute_variables(payload, enrollment_session, enrolled_user)
    process_scep_payloads(payload, enrollment_session, enrolled_user)
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
            unique_install_identifier=self.uuid,
        )

    def command_error(self):
        self.target.update_target_artifact(self.artifact_version, TargetArtifact.Status.FAILED)


register_command(InstallProfile)
