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
    ('appletv', TV),
    ('imac', DESKTOP),
    ('ipad', TABLET),
    ('iphone', MOBILE),
    ('mac13,1', DESKTOP),  # Mac Studio (2022)
    ('mac13,2', DESKTOP),  # Mac Studio (2022)
    ('mac14,10', LAPTOP),  # MacBook Pro (16-inch, 2023)
    ('mac14,12', DESKTOP),  # Mac mini (M2 Pro, 2023)
    ('mac14,2', LAPTOP),  # MacBook Air (M2, 2022)
    ('mac14,3', DESKTOP),  # Mac mini (M2, 2023)
    ('mac14,5', LAPTOP),  # MacBook Pro (14-inch, 2023)
    ('mac14,6', LAPTOP),  # MacBook Pro (16-inch, 2023)
    ('mac14,7', LAPTOP),  # MacBook Pro (13-inch, M2, 2022)
    ('mac14,9', LAPTOP),  # MacBook Pro (14-inch, 2023)
    ('macbook', LAPTOP),
    ('macmini', DESKTOP),
    ('macpro', DESKTOP),
    ('powermac', DESKTOP),
    ('virtualmac', VM),
    ('vmware', VM),
    ('xserve', SERVER),
    # DELL
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
        minor = int(match.group("minor")) - 4
        if minor < 8:
            # the patch letters are not always consecutive for older versions
            # probably because of the different architectures.
            raise ValueError("Cannot parse build str for macos < 10.8")
        if minor < 12:
            name = "OS X"
        else:
            name = "macOS"
        if minor >= 17:
            major = minor - 5
            minor = patch
            if build in ("21A558", "21A559", "21D62", "21E258", "21G83", "21G217",
                         "22A400", "22D68", "22E261", "22E772610a", "22F82", "22F770820b", "22F770820d", "22G90"):
                patch = 1
            elif build in ("21G309", "21G320", "22G91"):
                patch = 2
            elif build in ("21G417", "21G419"):
                patch = 3
            else:
                patch = 0
            if patch_letter >= "G" and patch_number >= 115:
                minor = 6
            elif minor > 0:
                minor -= 1
        elif minor == 16:
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
            elif build == "20G417":
                patch = 4
            elif build == "20G527":
                patch = 5
            elif build == "20G624":
                patch = 6
            elif build == "20G630":
                patch = 7
            elif build == "20G730":
                patch = 8
            else:
                patch = 0
        else:
            major = 10
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
