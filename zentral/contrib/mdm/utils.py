import logging
import plistlib
import uuid
from zentral.contrib.inventory.conf import macos_version_from_build
from .crypto import verify_signed_payload
from .models import Platform


logger = logging.getLogger("zentral.contrib.mdm.utils")


def model_from_machine_info(machine_info):
    return machine_info.get("PRODUCT")


def platform_and_os_from_machine_info(machine_info):
    # see https://github.com/apple/device-management/blob/release/other/machineinfo.yaml
    platform = None
    comparable_os_version = (0,)

    # platform
    model = model_from_machine_info(machine_info)
    if isinstance(model, str):
        model = model.upper()
        if "MAC" in model:
            platform = Platform.MACOS
        elif "IPHONE" in model:
            platform = Platform.IOS
        elif "IPAD" in model:
            platform = Platform.IPADOS
        elif "TV" in model:
            platform = Platform.TVOS
        else:
            logger.error("Unknown model %s platform", model)
    else:
        logger.error("Missing or invalid model in MachineInfo")

    # comparable OS version
    os_version = machine_info.get("OS_VERSION")
    if isinstance(os_version, str) and os_version:
        try:
            comparable_os_version = tuple(int(i) for i in os_version.split("."))
        except ValueError:
            logger.error("Could not parse OS version %s", os_version)
    else:
        logger.error("Missing or invalid OS_VERSION value in MachineInfo")
        if platform == Platform.MACOS:
            version = machine_info.get("VERSION")
            if isinstance(version, str):
                try:
                    os_version = macos_version_from_build(version)
                except ValueError:
                    logger.error("Could not parse build %s", version)
                else:
                    comparable_os_version = (os_version["major"], os_version["minor"], os_version["patch"])

    return platform, comparable_os_version


def get_provisioning_profile_info(data):
    try:
        _, payload = verify_signed_payload(data)
    except Exception:
        raise ValueError("Could not verify signature")
    try:
        info = plistlib.loads(payload)
    except Exception:
        raise ValueError("Invalid signed data")
    try:
        pp_uuid = uuid.UUID(info["UUID"])
    except Exception:
        raise ValueError("Could not read provisioning profile UUID")
    return info.get("Name") or "", pp_uuid, plistlib.dumps(info, fmt=plistlib.FMT_BINARY)
