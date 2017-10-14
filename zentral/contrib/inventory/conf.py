# machine snapshot platforms

LINUX = "LINUX"
MACOS = "MACOS"
WINDOWS = "WINDOWS"
ANDROID = "ANDROID"
IOS = "IOS"
PLATFORM_CHOICES = (
    (LINUX, 'Linux'),
    (MACOS, 'macOS'),
    (WINDOWS, 'Windows'),
    (ANDROID, 'Android'),
    (IOS, 'iOS'),
)

PLATFORM_CHOICES_DICT = dict(PLATFORM_CHOICES)

# machine snapshot types
DESKTOP = "DESKTOP"
LAPTOP = "LAPTOP"
MOBILE = "MOBILE"
SERVER = "SERVER"
TABLET = "TABLET"
VM = "VM"
TYPE_CHOICES = (
    (DESKTOP, 'Desktop'),
    (LAPTOP, 'Laptop'),
    (MOBILE, 'Mobile'),
    (SERVER, 'Server'),
    (TABLET, 'Tablet'),
    (VM, 'Virtual machine'),
)

TYPE_CHOICES_DICT = dict(TYPE_CHOICES)

# utils

HARDWARE_MODEL_SERIAL_MACHINE_TYPE_DICT = {
    'imac': DESKTOP,
    'ipad': TABLET,
    'iphone': MOBILE,
    'macbook': LAPTOP,
    'macmini': DESKTOP,
    'macpro': DESKTOP,
    'powermac': DESKTOP,
    'vmware': VM,
    'xserve': SERVER,
}


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
    elif "windows" in os_name:
        return WINDOWS
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
    system_info_t = tree.get("system_info", {})
    for attr in ("hardware_model", "hardware_serial"):
        val = system_info_t.get(attr)
        if val:
            val = val.lower()
            for prefix, ms_type in HARDWARE_MODEL_SERIAL_MACHINE_TYPE_DICT.items():
                if val.startswith(prefix):
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
