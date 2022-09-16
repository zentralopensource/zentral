import logging
from zentral.contrib.inventory.models import CurrentMachineSnapshot
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events
from .models import Blueprint, Platform


logger = logging.getLogger("zentral.contrib.mdm.inventory")


def tree_from_payload(udid, serial_number, meta_business_unit, payload):
    tree = {"source": {"module": "zentral.contrib.mdm",
                       "name": "MDM"},
            "reference": udid,
            "serial_number": serial_number}

    # BU
    try:
        tree["business_unit"] = meta_business_unit.api_enrollment_business_units()[0].serialize()
    except IndexError:
        pass

    # Mobile device IDs
    for attr in ("IMEI", "MEID"):
        val = payload.get(attr)
        if val:
            tree[attr.lower()] = val
    for service_subscription in payload.get("ServiceSubscriptions", []):
        for attr in ("IMEI", "MEID"):
            val = service_subscription.get(attr)
            if val:
                tree[attr.lower()] = val

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

    return tree


def commit_update_tree(enrolled_device, update_tree, missing_ok=False):
    # get existing tree
    try:
        cms = (CurrentMachineSnapshot.objects.select_for_update()
                                             .select_related("machine_snapshot")
                                             .get(serial_number=enrolled_device.serial_number,
                                                  source__module="zentral.contrib.mdm"))
    except CurrentMachineSnapshot.DoesNotExist:
        if missing_ok:
            tree = update_tree
        else:
            logger.warning("Could not update tree for machine %s: missing snapshot",
                           enrolled_device.serial_number)
            return
    else:
        tree = cms.tree
        if not tree:
            tree = cms.machine_snapshot.serialize()
    # update existing tree with new info
    tree.update(update_tree)
    # reset collected items if necessary
    blueprint = enrolled_device.blueprint
    for bp_attr, tree_attr in (("collect_apps", "osx_app_instances"),
                               ("collect_certificates", "certificates"),
                               ("collect_profiles", "profiles")):
        if blueprint is None or getattr(blueprint, bp_attr) == Blueprint.InventoryItemCollectionOption.NO:
            tree[tree_attr] = []
    # commit updated tree
    commit_machine_snapshot_and_trigger_events(tree)
    return tree
