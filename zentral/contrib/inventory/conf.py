import re

# machine snapshot platforms

LINUX = "LINUX"
MACOS = "MACOS"
WINDOWS = "WINDOWS"
ANDROID = "ANDROID"
IOS = "IOS"
IPADOS = "IPADOS"
TVOS = "TVOS"
PLATFORM_CHOICES = (
    (LINUX, 'Linux'),
    (MACOS, 'macOS'),
    (WINDOWS, 'Windows'),
    (ANDROID, 'Android'),
    (IOS, 'iOS'),
    (IPADOS, 'iPadOS'),
    (TVOS, 'tvOS'),
)

PLATFORM_CHOICES_DICT = dict(PLATFORM_CHOICES)

# machine snapshot types
DESKTOP = "DESKTOP"
EC2 = "EC2"
LAPTOP = "LAPTOP"
MOBILE = "MOBILE"
SERVER = "SERVER"
TABLET = "TABLET"
TV = "TV"
VM = "VM"
TYPE_CHOICES = (
    (DESKTOP, 'Desktop'),
    (EC2, 'EC2 instance'),
    (LAPTOP, 'Laptop'),
    (MOBILE, 'Mobile'),
    (SERVER, 'Server'),
    (TABLET, 'Tablet'),
    (TV, 'TV'),
    (VM, 'Virtual machine'),
)

TYPE_CHOICES_DICT = dict(TYPE_CHOICES)

# utils

HARDWARE_MODEL_SERIAL_MACHINE_TYPES = [
    # APPLE
    ('mac14,10', LAPTOP),
    ('mac14,12', DESKTOP),
    ('mac14,13', DESKTOP),
    ('mac14,14', DESKTOP),
    ('mac14,15', LAPTOP),
    ('mac15,10', LAPTOP),
    ('mac15,11', LAPTOP),
    ('mac15,12', LAPTOP),
    ('mac15,13', LAPTOP),
    ('mac15,14', DESKTOP),
    ('mac16,10', DESKTOP),
    ('mac16,11', DESKTOP),
    ('mac16,12', LAPTOP),
    ('mac16,13', LAPTOP),
    ('mac13,1', DESKTOP),
    ('mac13,2', DESKTOP),
    ('mac14,2', LAPTOP),
    ('mac14,3', DESKTOP),
    ('mac14,5', LAPTOP),
    ('mac14,6', LAPTOP),
    ('mac14,7', LAPTOP),
    ('mac14,8', DESKTOP),
    ('mac14,8', DESKTOP),
    ('mac14,9', LAPTOP),
    ('mac15,3', LAPTOP),
    ('mac15,4', DESKTOP),
    ('mac15,5', DESKTOP),
    ('mac15,6', LAPTOP),
    ('mac15,7', LAPTOP),
    ('mac15,8', LAPTOP),
    ('mac15,9', LAPTOP),
    ('mac16,1', LAPTOP),
    ('mac16,2', DESKTOP),
    ('mac16,3', DESKTOP),
    ('mac16,5', LAPTOP),
    ('mac16,6', LAPTOP),
    ('mac16,7', LAPTOP),
    ('mac16,8', LAPTOP),
    ('mac16,9', DESKTOP),
    ('mac17,2', LAPTOP),
    ('appletv', TV),
    ('imac', DESKTOP),
    ('ipad', TABLET),
    ('iphone', MOBILE),
    ('macbook', LAPTOP),
    ('macmini', DESKTOP),
    ('macpro', DESKTOP),
    ('powermac', DESKTOP),
    ('virtualmac', VM),
    ('vmware', VM),
    ('xserve', SERVER),
    # DELL
    ('pro micro', DESKTOP),
    ('inspiron 36', DESKTOP),
    ('inspiron 38', DESKTOP),
    ('inspiron 5', DESKTOP),
    ('inspiron 6', DESKTOP),
    ('latitude', LAPTOP),
    ('optiplex', DESKTOP),
    ('xps', LAPTOP),
    ('tower', DESKTOP),  # for precision tower
    ('precision', LAPTOP),  # after tower, so should be only laptops
    # GOOGLE
    ('google pixel slate', TABLET),
    ('google pixel', MOBILE),
    # HP
    ('hp elitebook', LAPTOP),
    ('hp zbook', LAPTOP),
    # HUAWEI
    ('huawei ane', MOBILE),
    ('huawei wgr', TABLET),
    # LENOVO
    ('thinkcentre', DESKTOP),
    ('thinkpad', LAPTOP),
    # SAMSUNG
    ('samsung gt-p', TABLET),
    ('samsung sm-a', MOBILE),
    ('samsung sm-g', MOBILE),
    ('samsung sm-p', TABLET),
    ('samsung sm-t', TABLET),
    # OTHERS
    ('virtual machine', VM),
]


# source http://www.techrepublic.com/blog/data-center/mac-address-scorecard-for-common-virtual-machine-platforms/
# last check 20161215
KNOWN_VM_MAC_PREFIXES = {
    '0003FF',  # Microsoft Corporation (Hyper-V, Virtual Server, Virtual PC)
    '005056', '000C29', '000569',  # VMware, Inc. (VMware ESX 3, Server, Workstation, Player)
    '00163E',  # Xensource, Inc.
    '001C42',  # Parallels, Inc.
    '080027',  # PCS Systemtechnik GmbH (VirtualBox)
}


def platform_with_os_name(os_name):
    if not os_name:
        return
    os_name = os_name.lower().replace(" ", "")
    if "macos" in os_name or "osx" in os_name:
        return MACOS
    elif "ios" in os_name:
        return IOS
    elif "ipados" in os_name:
        return IPADOS
    elif "tvos" in os_name:
        return TVOS
    elif "windows" in os_name:
        return WINDOWS
    elif "android" in os_name:
        return ANDROID
    else:
        for distro in ('centos', 'fedora', 'redhat', 'rehl',
                       'debian', 'ubuntu',
                       'gentoo',
                       'linux'):
            if distro in os_name:
                return LINUX


def update_ms_tree_platform(tree):
    os_version_t = tree.get("os_version", {})
    os_name = os_version_t.get("name")
    platform = platform_with_os_name(os_name)
    if platform:
        tree["platform"] = platform


def update_ms_tree_type(tree):
    if tree.get("ec2_instance_metadata"):
        tree["type"] = EC2
        return
    system_info_t = tree.get("system_info", {})
    for attr in ("hardware_model", "hardware_serial"):
        val = system_info_t.get(attr)
        if val:
            val = val.lower()
            for search_str, ms_type in HARDWARE_MODEL_SERIAL_MACHINE_TYPES:
                if search_str in val:
                    tree["type"] = ms_type
                    return
    network_interfaces = tree.get("network_interfaces")
    if network_interfaces and \
       all(isinstance(ni.get("mac"), str) and ni["mac"].replace(":", "")[:6].upper() in KNOWN_VM_MAC_PREFIXES
           for ni in network_interfaces):
        tree["type"] = VM
        return
    cpu_brand = system_info_t.get("cpu_brand")
    if cpu_brand and "xeon" in cpu_brand.lower():
        tree["type"] = SERVER


def has_deb_packages(machine_snapshot):
    os_version = machine_snapshot.os_version
    if not os_version:
        return False
    os_name = os_version.name
    if not os_name:
        return False
    os_name = os_name.lower()
    return "ubuntu" in os_name or "debian" in os_name


# OSVersion utils


def is_apple_os(os_name):
    if not isinstance(os_name, str):
        return False
    os_name = os_name.lower()
    return any(s in os_name for s in ("macos", "ios", "ipados", "os x", "tvos", "watchos"))


def os_version_version_display(os_version_d):
    items = []
    os_name = os_version_d.get("name")
    drop_patch_zero = is_apple_os(os_name)
    number = ".".join(
        str(num) for num, attr in ((os_version_d.get(attr), attr) for attr in ("major", "minor", "patch"))
        if num is not None and (attr != "patch" or not drop_patch_zero or num != 0)
    )
    if not os_name or number not in os_name:
        items.append(number)
    version = os_version_d.get("version")
    if version:
        items.append(version)
    return " ".join(items)


def os_version_display(os_version_d):
    items = []
    name = os_version_d.get("name")
    if name:
        items.append(name)
    version = os_version_version_display(os_version_d)
    if version:
        items.append(version)
    build = os_version_d.get("build")
    if build:
        items.append(f"({build})")
    return " ".join(items)


# macOS versions


MACOS_BUILD_RE = re.compile(
    r"\A"
    r"(?P<minor>[0-9]{1,2})"
    r"(?P<patch_letter>[A-Z])"
    r"(?P<patch_number>[0-9]+)"
    r"(?P<beta>[a-z]+)?"
    r"\Z"
)


def macos_version_from_build(build):
    match = MACOS_BUILD_RE.match(build)
    if match:
        patch_letter = match.group("patch_letter")
        patch_number = int(match.group("patch_number"))
        patch = ord(patch_letter) - 65
        minor = int(match.group("minor"))
        if minor < 12:
            # the patch letters are not always consecutive for older versions
            # probably because of the different architectures.
            raise ValueError("Cannot parse build str for macos < 10.8")
        if minor < 16:
            name = "OS X"
        else:
            name = "macOS"
        if minor >= 21:
            if minor <= 24:
                major = minor - 9
            else:
                major = minor + 1
            minor = patch
            if build in ("21A558", "21A559", "21D62", "21E258", "21G83", "21G217", "21G920",
                         "22A400", "22D68", "22E261", "22E772610a", "22F82", "22F770820b", "22F770820d",
                         "22G90", "22G313", "22H221",
                         "23B81", "23B2082", "23C71", "23D60", "23G93", "23H222", "23J30",
                         "24A348", "24B91", "24D70", "24E263", "24G90", "24G231",
                         "25A362"):
                patch = 1
            elif build in ("21G309", "21G320", "21G1974",
                           "22G91", "22G320", "22H313",
                           "23B2091", "23B92", "23H311", "23J126",
                           "24D81", "24G325"):
                patch = 2
            elif build in ("21G417", "21G419", "21H1015",
                           "22G436", "22H417",
                           "23H417"):
                patch = 3
            elif build in ("21G526", "21H1123", "22G513", "22H420", "23H420"):
                patch = 4
            elif build in ("21G531", "21H1222", "22G621", "22H527", "23H527"):
                patch = 5
            elif build in ("21G646", "21H1320", "22G630", "22H625", "23H626"):
                patch = 6
            elif build in ("21G651", "22G720", "22H722", "23H723"):
                patch = 7
            elif build in ("21G725", "22G820", "22H730", "23H730"):
                patch = 8
            elif build in ("21G726", "22G830"):
                patch = 9
            else:
                patch = 0
            if patch_letter >= "G" and major == 15 and patch_number >= 222:
                minor = 7
            elif patch_letter >= "G" and major == 12 and patch_number >= 816:
                minor = 7
            elif patch_letter == "G" and major in (12, 13) and patch_number >= 115:
                minor = 6
            elif (
                   (patch_letter < "H" and minor > 0 and major < 14)
                   or (patch_letter >= "J" and major == 14)
            ):
                minor -= 1
        elif minor == 20:
            major = 11
            if patch_letter >= "G" and patch_number >= 817:
                minor = 7
            elif patch_letter >= "G" and patch_number >= 165:
                minor = 6
            else:
                minor = max(0, patch - 1)
            if build in ("20B29", "20B50", "20D74", "20D75", "20E241", "20G80", "20G224", "20G918"):
                patch = 1
            elif build in ("20D80", "20G95", "20G314", "20G1008", "20G1020"):
                patch = 2
            elif build in ("20D91", "20G415", "20G1116"):
                patch = 3
            elif build in ("20G417", "20G1120"):
                patch = 4
            elif build in ("20G527", "20G1225"):
                patch = 5
            elif build in ("20G624", "20G1231"):
                patch = 6
            elif build in ("20G630", "20G1345"):
                patch = 7
            elif build in ("20G730", "20G1351"):
                patch = 8
            elif build == "20G1426":
                patch = 9
            elif build == "20G1427":
                patch = 10
            else:
                patch = 0
        else:
            major = 10
            minor -= 4
        os_version = {
            "name": name,
            "major": major,
            "minor": minor,
            "patch": patch,
            "build": build
        }
        # RSR
        if build in ("22E772610a", "22F770820b"):
            os_version["version"] = "(a)"
        elif build == "22F770820d":
            os_version["version"] = "(c)"
        return os_version
    else:
        raise ValueError("Bad build number")


# Windows versions


WINDOWS_BUILD_VERSIONS = {
    # Windows 11
    26300: "26H2",
    28000: "26H1",
    26200: "25H2",
    26100: "24H2",
    22631: "23H2",
    22621: "22H2",
    22000: "21H2",
    # Windows 10
    19044: "21H2",
    19043: "21H1",
    19042: "20H2",
    19041: "2004",
    18363: "1909",
    18362: "1903",
    17763: "1809",
    17134: "1803",
    16299: "1709",
    15063: "1703",
    14393: "1607",
    10586: "1511",
    10240: "1507",
}


def windows_version_from_build(build):
    try:
        build_major = int(build.split(".")[0])
    except Exception:
        raise ValueError("Bad build number")
    try:
        version = WINDOWS_BUILD_VERSIONS[build_major]
    except KeyError:
        raise ValueError("Unknown build number")
    if build_major >= 22000:
        major = 11
    else:
        major = 10
    return {
        "name": f"Windows {major}",
        "major": major,
        "build": build,
        "version": version,
    }


def cleanup_windows_os_version(os_version):
    build = os_version.get("build")
    patch = os_version.get("patch")
    if isinstance(patch, int):
        if isinstance(build, str):
            build = f"{patch}.{build}"
        else:
            build = str(patch)
    if build:
        try:
            return windows_version_from_build(build)
        except ValueError:
            pass
        os_version["build"] = build
    if isinstance(patch, int):
        os_version.pop("patch")
        if patch >= 10000:
            os_version.pop("minor", None)
            if patch >= 22000:
                os_version["name"] = "Windows 11"
                os_version["major"] = 11
            else:
                os_version["name"] = "Windows 10"
                os_version["major"] = 10
            return os_version
    # TODO: better?
    os_version["name"] = "Windows"
    return os_version


# Mac secure enclave


APPLE_MODEL_RE = re.compile(r"^([a-zA-Z]+)([0-9]+)(?:,([0-9]+))$")


def mac_secure_enclave_from_model(model):
    if not isinstance(model, str):
        return
    if model in ("MacBookPro13,2", "MacBookPro13,3", "MacBookPro14,2", "MacBookPro14,3"):
        return "T1"
    elif model in ("iMac20,1", "iMacPro1,1", "MacPro7,1", "Macmini8,1",
                   "MacBookAir8,1", "MacBookAir8,2", "MacBookAir9,1",
                   "MacBookPro15,1", "MacBookPro15,2", "MacBookPro15,3", "MacBookPro15,4",
                   "MacBookPro16,1", "MacBookPro16,2", "MacBookPro16,3", "MacBookPro16,4"):
        return "T2"
    else:
        m = APPLE_MODEL_RE.match(model)
        if m:
            product, major, _ = m.groups()
            if product == "Mac":
                return "SILICON"
            else:
                major = int(major)
                if (
                    (product == "MacBookPro" and major >= 17)
                    or (product == "MacBookAir" and major >= 10)
                    or (product == "iMac" and major >= 21)
                    or (product == "Macmini" and major >= 9)
                ):
                    return "SILICON"
