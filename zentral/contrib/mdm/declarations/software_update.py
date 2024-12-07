from datetime import datetime, timedelta
import hashlib
import logging
from zentral.utils.time import naive_truncated_isoformat
from zentral.contrib.mdm.software_updates import best_available_software_update
from .exceptions import DeclarationError
from .utils import get_blueprint_declaration_identifier


__all__ = ["get_software_update_enforcement_specific_identifier", "build_specific_software_update_enforcement"]


logger = logging.getLogger("zentral.contrib.mdm.declarations.software_update")


def get_software_update_enforcement_specific_identifier(target):
    return get_blueprint_declaration_identifier(target.blueprint, "softwareupdate-enforcement-specific")


# https://github.com/apple/device-management/blob/release/declarative/declarations/configurations/softwareupdate.enforcement.specific.yaml  # NOQA
def build_specific_software_update_enforcement(target, missing_ok=False):
    software_update_enforcement = target.software_update_enforcement
    if not software_update_enforcement:
        if missing_ok:
            return
        raise DeclarationError("No software enforcement found for target")
    if software_update_enforcement.max_os_version:
        software_update = best_available_software_update(
            target.enrolled_device,
            max_os_version=software_update_enforcement.max_os_version,
        )
        if not software_update:
            raise DeclarationError("No software update available for target")
        local_datetime = (
            datetime.combine(software_update.availability.lower, software_update_enforcement.local_time)
            + timedelta(days=software_update_enforcement.delay_days)
        )
        target_os_version = software_update.target_os_version()
        target_build_version = software_update.build
        if not target_build_version and target_os_version == target.enrolled_device.current_os_version:
            # TODO remove this it is confirmed that we always get the build from the feed
            target_build_version = target.enrolled_device.current_build_version
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
