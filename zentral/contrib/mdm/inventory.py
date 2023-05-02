import logging
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events
from zentral.contrib.mdm.models import Blueprint, CommandStatus, DeviceCommand, Platform
from zentral.contrib.mdm.commands.base import load_command


logger = logging.getLogger("zentral.contrib.mdm.inventory")


def ms_tree_from_payload(payload):
    ms_tree = {}

    # Mobile device IDs
    for attr in ("IMEI", "MEID"):
        val = payload.get(attr)
        if val:
            ms_tree[attr.lower()] = val
    for service_subscription in payload.get("ServiceSubscriptions", []):
        for attr in ("IMEI", "MEID"):
            val = service_subscription.get(attr)
            if val:
                ms_tree[attr.lower()] = val

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
        ms_tree["system_info"] = system_info_d

    # OS Version
    os_version = payload.get("OSVersion")
    os_version_extra = payload.get("SupplementalOSVersionExtra")
    build_version = payload.get("BuildVersion")
    build_version_extra = payload.get("SupplementalBuildVersion")
    if os_version:
        d = dict(zip(('major', 'minor', 'patch'),
                     (int(s) for s in os_version.split('.'))))
        if "patch" not in d:
            d["patch"] = 0
        if os_version_extra:
            d["version"] = os_version_extra
        if build_version_extra:
            d["build"] = build_version_extra
        elif build_version:
            d["build"] = build_version
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
        ms_tree["os_version"] = d

    return ms_tree


def update_inventory_tree(command, commit_enrolled_device=True):
    """Used in the inventory MDM commands to update the inventory tree

    Search for the other latest inventory MDM command to build a complete machine snapshot tree."""
    enrolled_device = command.enrolled_device
    blueprint = enrolled_device.blueprint
    ms_tree = {
        "source": {"module": "zentral.contrib.mdm",
                   "name": "MDM"},
        "reference": enrolled_device.udid,
        "serial_number": enrolled_device.serial_number
    }
    try:
        ms_tree["business_unit"] = command.meta_business_unit.api_enrollment_business_units()[0].serialize()
    except IndexError:
        pass

    for bp_attr, cmd_db_name, ts_attr in (
        (None, "DeviceInformation", "device_information_updated_at"),
        ("collect_apps", "InstalledApplicationList", "apps_updated_at"),
        ("collect_certificates", "CertificateList", "certificates_updated_at"),
        ("collect_profiles", "ProfileList", "profiles_updated_at")
    ):
        if (
            bp_attr is not None
            and (
                blueprint is None
                or getattr(blueprint, bp_attr) == Blueprint.InventoryItemCollectionOption.NO
            )
        ):
            # Skip inventory information
            continue

        latest_command = None
        if command.get_db_name() == cmd_db_name:
            latest_command = command
        else:
            latest_db_command = DeviceCommand.objects.filter(
                enrolled_device=enrolled_device,
                name=cmd_db_name,
                result__isnull=False,
                status=CommandStatus.Acknowledged.value
            ).order_by("-created_at").first()
            if latest_db_command:
                latest_command = load_command(latest_db_command)
        if latest_command:
            ms_tree.update(latest_command.get_inventory_partial_tree())
            setattr(enrolled_device, ts_attr, latest_command.result_time)

    commit_machine_snapshot_and_trigger_events(ms_tree)

    if commit_enrolled_device:
        enrolled_device.save()

    return ms_tree
