from django.urls import reverse


def tree_from_payload(udid, serial_number, meta_business_unit, payload):
    url = reverse("mdm:device", args=(serial_number,))
    tree = {"source": {"module": "zentral.contrib.mdm",
                       "name": "MDM"},
            "reference": udid,
            "serial_number": serial_number,
            "links": [{"anchor_text": "info", "url": url}]}

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
                          ("hardware_model", "ModelName"),
                          ("hardware_serial", "Model"),
                          ("hardware_serial", "ProductName")):
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
            if "IPOD" in hardware_model or "IPAD" in hardware_model or "IPHONE" in hardware_model:
                d["name"] = "iOS"
            elif "WATCH" in hardware_model:
                d["name"] = "watchOS"
            elif "TV" in hardware_model:
                d["name"] = "tvOS"
            else:
                d["name"] = "macOS"
        tree["os_version"] = d
    return tree


def parse_dn(dn):
    # TODO: poor man's DN parser
    d = {}
    current_attr = ""
    current_val = ""

    state = "ATTR"
    string_state = "NOT_ESCAPED"
    for c in dn:
        if c == "\\" and string_state == "NOT_ESCAPED":
            string_state = "ESCAPED"
        else:
            if string_state == "NOT_ESCAPED" and c in "=,":
                if c == "=":
                    state = "VAL"
                elif c == ",":
                    state = "ATTR"
                    if current_attr:
                        d[current_attr] = current_val
                    current_attr = current_val = ""
            else:
                if state == "ATTR":
                    current_attr += c
                elif state == "VAL":
                    current_val += c
                if string_state == "ESCAPED":
                    string_state = "NOT_ESCAPED"

    if current_attr:
        d[current_attr] = current_val
        current_attr = current_val = ""
    return d
