from datetime import datetime, timedelta
import logging
from django.http import Http404
from django.urls import reverse
from zentral.conf import settings
from zentral.utils.payloads import get_payload_identifier
from zentral.contrib.mdm.models import Artifact


logger = logging.getLogger("zentral.contrib.mdm.declarations")


def get_declaration_identifier(blueprint, *suffixes):
    return get_payload_identifier("blueprint", blueprint.pk, *suffixes)


# https://developer.apple.com/documentation/devicemanagement/managementstatussubscriptions
# https://developer.apple.com/documentation/devicemanagement/status_reports
def build_target_management_status_subscriptions(target):
    return {
        "Identifier": get_declaration_identifier(target.blueprint, "management-status-subscriptions"),
        "Payload": {
            "StatusItems": [
                {"Name": "device.identifier.serial-number"},
                {"Name": "device.identifier.udid"},
                {"Name": "device.model.family"},
                {"Name": "device.model.identifier"},
                {"Name": "device.model.marketing-name"},
                {"Name": "device.operating-system.build-version"},
                {"Name": "device.operating-system.family"},
                {"Name": "device.operating-system.marketing-name"},
                {"Name": "device.operating-system.version"},
                {"Name": "mdm.app"},
                {"Name": "passcode.is-compliant"},
                {"Name": "passcode.is-present"},
                {"Name": "management.client-capabilities"},
                {"Name": "management.declarations"},
                {"Name": "management.push-token"},
            ]
        },
        "ServerToken": "2",  # We start with hard-coded one, because it will not change at first
        "Type": "com.apple.configuration.management.status-subscriptions"
    }


def get_legacy_profile_identifier(artifact):
    return get_payload_identifier("legacy-profile", artifact["pk"])


def get_legacy_profile_server_token(target, artifact, artifact_version):
    elements = [artifact_version["pk"]]
    reinstall_on_os_update = Artifact.ReinstallOnOSUpdate(artifact["reinstall_on_os_update"])
    if reinstall_on_os_update != Artifact.ReinstallOnOSUpdate.NO:
        slice_length = None
        if reinstall_on_os_update == Artifact.ReinstallOnOSUpdate.MAJOR:
            slice_length = 1
        elif reinstall_on_os_update == Artifact.ReinstallOnOSUpdate.MINOR:
            slice_length = 2
        elif reinstall_on_os_update == Artifact.ReinstallOnOSUpdate.PATCH:
            slice_length = 3
        if slice_length:
            elements.append("ov-{}".format(".".join(str(i) for i in target.comparable_os_version[:slice_length])))
    reinstall_interval = artifact["reinstall_interval"]
    if reinstall_interval:
        install_num = int((datetime.utcnow() - target.target.created_at) / timedelta(seconds=reinstall_interval))
        elements.append(f"ri-{install_num}")
    return ".".join(elements)


# https://developer.apple.com/documentation/devicemanagement/legacyprofile
def build_legacy_profile(target, declaration_identifier):
    artifact_pk = declaration_identifier.split(".")[-1]
    profile_artifact_version = profile_artifact = None
    for artifact, artifact_version in target.all_in_scope_serialized(included_types=(Artifact.Type.PROFILE,)):
        if artifact["pk"] == artifact_pk:
            profile_artifact = artifact
            profile_artifact_version = artifact_version
            break
    if not profile_artifact_version:
        raise Http404
    return {
        "Type": "com.apple.configuration.legacy",
        "Identifier": get_legacy_profile_identifier(profile_artifact),
        "ServerToken": get_legacy_profile_server_token(target, profile_artifact, profile_artifact_version),
        "Payload": {
            "ProfileURL": "https://{}{}".format(
                settings["api"]["fqdn_mtls"],  # TODO signed requests on FQDN ?
                reverse("mdm_public:profile_download_view", args=(profile_artifact_version["pk"],))
            )
        },
    }
