from hashlib import md5
import logging
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events
from .models import Platform


logger = logging.getLogger("zentral.contrib.mdm.utils")


MD5_SIZE = 10 * 2**20  # 10MB


def get_md5s(package_file, md5_size=MD5_SIZE):
    file_chunk_size = 64 * 2**10  # 64KB
    md5_size = (md5_size // file_chunk_size) * file_chunk_size
    md5s = []
    h = md5()
    current_size = 0
    for chunk in package_file.chunks(chunk_size=file_chunk_size):
        h.update(chunk)
        current_size += len(chunk)
        if current_size == md5_size:
            md5s.append(h.hexdigest())
            h = md5()
            current_size = 0
    if current_size:
        md5s.append(h.hexdigest())
        if len(md5s) == 1:
            md5_size = current_size
    return md5_size, md5s


def build_manifest(title, package_file, pkg_refs):
    md5_size, md5s = get_md5s(package_file)
    asset = {"kind": "software-package",
             "md5-size": md5_size,
             "md5s": md5s}
    metadata = {"kind": "software", "title": title, "sizeInBytes": package_file.size}
    # we will add the url dynamically
    bundles = [{"bundle-identifier": pkg_ref["id"],
                "bundle-version": pkg_ref["version"]}
               for pkg_ref in pkg_refs]
    metadata.update(bundles.pop(0))
    if bundles:
        metadata["items"] = bundles
    return {"items": [{"assets": [asset], "metadata": metadata}]}


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

    # OS Version
    os_version = payload.get("OSVersion")
    build_version = payload.get("BuildVersion")
    if os_version:
        d = dict(zip(('major', 'minor', 'patch'),
                     (int(s) for s in os_version.split('.'))))
        if build_version:
            d["build"] = build_version
        tree["os_version"] = d

    # System Info
    system_info_d = {}
    for si_attr, attr in (("computer_name", "DeviceName"),
                          ("hardware_model", "Model"),  # MacBookPro11,1
                          ("hardware_serial", "SerialNumber")):
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
