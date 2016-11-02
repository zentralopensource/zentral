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

HARDWARE_MODEL_MACHINE_TYPE_DICT = {
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


def update_ms_tree_platform(tree):
    os_version_t = tree.get("os_version", {})
    os_name = os_version_t.get("name", None)
    try:
        minor = int(os_version_t.get("minor", None))
    except (TypeError, ValueError):
        minor = None
    if not os_name:
        return
    os_name = os_name.lower()
    os_name_split = os_name.split()
    if len(os_name_split) == 2 and \
       os_name_split[0][0] == os_name_split[1][0] and \
       (minor == 4 or minor == 10):
        # ubuntu
        tree["platform"] = LINUX
        return
    os_name = os_name.replace(" ", "")
    if "osx" in os_name:
        tree["platform"] = MACOS
    elif "ios" in os_name:
        tree["platform"] = IOS
    elif "ubuntu" in os_name:
        tree["platform"] = LINUX


def update_ms_tree_type(tree):
    system_info_t = tree.get("system_info", {})
    hardware_model = system_info_t.get("hardware_model", None)
    if hardware_model:
        hardware_model = hardware_model.lower()
        for prefix, ms_type in HARDWARE_MODEL_MACHINE_TYPE_DICT.items():
            if hardware_model.startswith(prefix):
                tree["type"] = ms_type
                return
    else:
        cpu_brand = system_info_t.get("cpu_brand", None)
        if cpu_brand and "xeon" in cpu_brand.lower():
            tree["type"] = SERVER
