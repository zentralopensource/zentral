from datetime import datetime, timedelta
import hashlib
import logging
from django.contrib.contenttypes.models import ContentType
from django.core import signing
from django.http import Http404
from django.urls import reverse
from zentral.conf import settings
from zentral.utils.payloads import get_payload_identifier
from zentral.utils.time import naive_truncated_isoformat
from .models import Artifact, ArtifactVersion, EnrolledUser
from .software_updates import iter_available_software_updates


logger = logging.getLogger("zentral.contrib.mdm.declarations")


def get_declaration_identifier(blueprint, *suffixes):
    return get_payload_identifier("blueprint", blueprint.pk, *suffixes)


# https://developer.apple.com/documentation/devicemanagement/managementstatussubscriptions
# https://developer.apple.com/documentation/devicemanagement/status_reports
def build_target_management_status_subscriptions(target):
    status_items = []
    if target.client_capabilities:
        try:
            supported_status_items = target.client_capabilities["supported-payloads"]["status-items"]
        except KeyError:
            logger.warning("Target %s: could not find supported status items", target)
        else:
            status_items = [si for si in supported_status_items if not si.startswith("test.")]
    if not status_items:
        # default status items supported by all clients
        status_items = [
            "device.identifier.serial-number",
            "device.identifier.udid",
            "device.model.family",
            "device.model.identifier",
            "device.model.marketing-name",
            "device.operating-system.build-version",
            "device.operating-system.family",
            "device.operating-system.marketing-name",
            "device.operating-system.version",
            "management.client-capabilities",
            "management.declarations",
        ]
    status_items.sort()
    payload = {"StatusItems": []}
    h = hashlib.sha1()
    for status_item in sorted(status_items):
        h.update(status_item.encode("utf-8"))
        payload["StatusItems"].append({"Name": status_item})
    return {
        "Identifier": get_declaration_identifier(target.blueprint, "management-status-subscriptions"),
        "Payload": payload,
        "ServerToken": h.hexdigest(),
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


def dump_legacy_profile_token(enrollment_session, target, artifact_version_pk):
    if not isinstance(artifact_version_pk, str):
        artifact_version_pk = str(artifact_version_pk)
    payload = {"avpk": artifact_version_pk,
               "esm": enrollment_session._meta.model_name,
               "espk": enrollment_session.pk}
    if target.enrolled_user:
        payload["eupk"] = target.enrolled_user.pk
    return signing.dumps(payload, salt="zentral_mdm_legacy_profile")


def load_legacy_profile_token(token):
    payload = signing.loads(token, salt="zentral_mdm_legacy_profile")
    # profile
    artifact_version = ArtifactVersion.objects.select_related("profile").get(
        pk=payload["avpk"],
        artifact__type=Artifact.Type.PROFILE
    )
    # enrollment session
    es_ct = ContentType.objects.get_by_natural_key("mdm", payload["esm"])
    enrollment_session = (es_ct.model_class()
                               .objects
                               .select_related("enrolled_device", "realm_user")
                               .get(pk=payload["espk"]))
    # enrolled user
    try:
        enrolled_user = EnrolledUser.objects.get(pk=payload["eupk"])
    except KeyError:
        enrolled_user = None
    return artifact_version.profile, enrollment_session, enrolled_user


# https://developer.apple.com/documentation/devicemanagement/legacyprofile
def build_legacy_profile(enrollment_session, target, declaration_identifier):
    # artifact version
    artifact_pk = declaration_identifier.split(".")[-1]
    profile_artifact_version = profile_artifact = None
    for artifact, artifact_version in target.all_installed_or_to_install_serialized((Artifact.Type.PROFILE,)):
        if artifact["pk"] == artifact_pk:
            profile_artifact = artifact
            profile_artifact_version = artifact_version
            break
    if not profile_artifact_version:
        raise Http404
    # signed URL
    return {
        "Type": "com.apple.configuration.legacy",
        "Identifier": get_legacy_profile_identifier(profile_artifact),
        "ServerToken": get_legacy_profile_server_token(target, profile_artifact, profile_artifact_version),
        "Payload": {
            "ProfileURL": "https://{}{}".format(
                settings["api"]["fqdn"],
                reverse("mdm_public:profile_download_view",
                        args=(dump_legacy_profile_token(enrollment_session, target, artifact_version["pk"]),))
            )
        },
    }


def get_software_update_enforcement_specific_identifier(target):
    return get_declaration_identifier(target.blueprint, "softwareupdate-enforcement-specific")


# https://github.com/apple/device-management/blob/release/declarative/declarations/configurations/softwareupdate.enforcement.specific.yaml  # NOQA
def build_specific_software_update_enforcement(target):
    software_update_enforcement = target.software_update_enforcement
    if not software_update_enforcement:
        return
    if software_update_enforcement.max_os_version:
        software_update = None
        for software_update in iter_available_software_updates(
            target.enrolled_device,
            max_os_version=software_update_enforcement.max_os_version
        ):
            break
        if not software_update:
            logger.warning("Target %s: no software update available", target)
            return
        local_datetime = (
            datetime.combine(software_update.availability.lower, software_update_enforcement.local_time)
            + timedelta(days=software_update_enforcement.delay_days)
        )
        target_os_version = str(software_update)
        if target_os_version == target.enrolled_device.current_os_version:
            target_build_version = target.enrolled_device.current_build_version
        else:
            target_build_version = None
    else:
        local_datetime = software_update_enforcement.local_datetime
        target_os_version = software_update_enforcement.os_version
        target_build_version = software_update_enforcement.build_version
    payload = {
        "TargetOSVersion": target_os_version,
        "TargetLocalDateTime": naive_truncated_isoformat(local_datetime),
    }
    if target_build_version:
        payload["TargetBuildVersion"] = target_build_version
    if software_update_enforcement.details_url:
        payload["DetailsURL"] = software_update_enforcement.details_url
    h = hashlib.sha1()
    for attr, val in sorted(payload.items()):
        h.update(attr.encode("utf-8"))
        h.update(val.encode("utf-8"))
    return {
        "Identifier": get_software_update_enforcement_specific_identifier(target),
        "Type": "com.apple.configuration.softwareupdate.enforcement.specific",
        "ServerToken": h.hexdigest(),
        "Payload": payload,
    }
