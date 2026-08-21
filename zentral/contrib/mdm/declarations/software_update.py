from datetime import datetime, timedelta
import hashlib
import logging
from zentral.utils.time import naive_truncated_isoformat
from zentral.contrib.mdm.models import SoftwareUpdate
from zentral.contrib.mdm.software_updates import best_available_software_update
from .exceptions import DeclarationError
from .utils import get_blueprint_declaration_identifier


__all__ = ["get_software_update_enforcement_specific_identifier", "build_specific_software_update_enforcement",
           "get_specific_software_update_enforcement"]


logger = logging.getLogger("zentral.contrib.mdm.declarations.software_update")


def get_software_update_enforcement_specific_identifier(target):
    return get_blueprint_declaration_identifier(target.blueprint, "softwareupdate-enforcement-specific")


# https://github.com/apple/device-management/blob/release/declarative/declarations/configurations/softwareupdate.enforcement.specific.yaml  # NOQA
def build_specific_software_update_enforcement(target):
    """Build the softwareupdate.enforcement.specific declaration, or return None if there is nothing to enforce.

    Must not raise: the activation and the declaration items advertise this declaration if and only if this
    returns one, and a target whose enforcement cannot be resolved has to keep the rest of its declarations.
    """
    software_update_enforcement = target.software_update_enforcement
    if not software_update_enforcement:
        return
    enrolled_device = target.enrolled_device
    if software_update_enforcement.max_os_version:
        if software_update_enforcement.local_time is None or software_update_enforcement.delay_days is None:
            logger.error("Software update enforcement %s: missing local time or delay in days",
                         software_update_enforcement.pk)
            return
        device_information = enrolled_device.device_information
        if not isinstance(device_information, dict) or not device_information.get("SoftwareUpdateDeviceID"):
            # the device has not reported its inventory yet, there is nothing to look up the feed with
            logger.info("Enrolled device %s: no software update device ID", enrolled_device.udid)
            return
        software_update = best_available_software_update(
            enrolled_device,
            max_os_version=software_update_enforcement.max_os_version,
        )
        if not software_update:
            if SoftwareUpdate.objects.exists():
                logger.error("Enrolled device %s: no software update available", enrolled_device.udid)
            else:
                # nothing has ever been synced from the Apple software lookup service, or every update
                # available for the fleet has expired. No device can be enforced in this state.
                logger.error("Enrolled device %s: empty software update feed", enrolled_device.udid)
            return
        if software_update.full_comparable_os_version < enrolled_device.comparable_os_version:
            logger.info("Enrolled device %s: software update %s below the device OS version",
                        enrolled_device.udid, software_update)
            return
        local_datetime = (
            datetime.combine(software_update.availability.lower, software_update_enforcement.local_time)
            + timedelta(days=software_update_enforcement.delay_days)
        )
        target_os_version = software_update.target_os_version()
        target_build_version = software_update.build
        if not target_build_version and target_os_version == enrolled_device.current_os_version:
            # TODO remove this it is confirmed that we always get the build from the feed
            target_build_version = enrolled_device.current_build_version
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


def get_specific_software_update_enforcement(target):
    declaration = target.software_update_enforcement_declaration
    if declaration:
        return declaration
    if not target.software_update_enforcement:
        raise DeclarationError("No software enforcement found for target")
    raise DeclarationError("No software update available for target")
