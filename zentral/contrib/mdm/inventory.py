import logging
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events
from .models import Platform


logger = logging.getLogger("zentral.contrib.mdm.inventory")


def commit_tree_from_payload(udid, serial_number, meta_business_unit, payload):
    tree = {"source": {"module": "zentral.contrib.mdm",
                       "name": "MDM"},
            "reference": udid,
            "serial_number": serial_number}

    # Mobile device IDs
    for attr in ("IMEI", "MEID"):
        val = payload.get(attr)
        if val:
            tree[attr.lower()] = val

    # BU
    try:
        tree["business_unit"] = meta_business_unit.api_enrollment_business_units()[0].serialize()
    except IndexError:
        pass

    # System Info
    system_info_d = {}
    for si_attr, attr in (("computer_name", "DeviceName"),
                          ("hardware_model", "ProductName"),  # iPad5,2, seen during User Enrollment
                          ("hardware_model", "Model"),  # MacBookPro11,1
                          ("hardware_serial", "SerialNumber")):
        if system_info_d.get(si_attr):
            continue
        val = payload.get(attr)
        if val:
            system_info_d[si_attr] = val
    if system_info_d:
        tree["system_info"] = system_info_d

    # OS Version
    os_version = payload.get("OSVersion")
    build_version = payload.get("BuildVersion")
    if os_version:
        d = dict(zip(('major', 'minor', 'patch'),
                     (int(s) for s in os_version.split('.'))))
        if build_version:
            d["build"] = build_version
        if "patch" not in d:
            d["patch"] = 0
        hardware_model = system_info_d.get("hardware_model")
        if hardware_model:
            hardware_model = hardware_model.upper()
            if "IPOD" in hardware_model or "IPHONE" in hardware_model:
                d["name"] = Platform.iOS.value
            elif "IPAD" in hardware_model:
                if d["major"] >= 13:
                    d["name"] = Platform.iPadOS.value
                else:
                    d["name"] = Platform.iOS.value
            elif "TV" in hardware_model:
                d["name"] = Platform.tvOS.value
            else:
                # No watchOS
                d["name"] = Platform.macOS.value
        tree["os_version"] = d

    commit_machine_snapshot_and_trigger_events(tree)

    return tree
