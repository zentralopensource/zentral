import random
import requests
import string
import uuid as uuid_mod


SYSTEM_INFOS = [
    {'cpu_brand': 'Apple M1',
     'cpu_logical_cores': '8',
     'cpu_physical_cores': '8',
     'cpu_subtype': 'ARM64E',
     'cpu_type': 'arm64e',
     'hardware_model': 'MacBook Air (M1, 2020)',
     'physical_memory': '17179869184'},
    {'cpu_brand': 'Intel(R) Core(TM) i7-1068NG7 CPU @ 2.30GHz',
     'cpu_logical_cores': '8',
     'cpu_physical_cores': '4',
     'cpu_subtype': 'Intel x86-64h Haswell',
     'cpu_type': 'x86_64h',
     'hardware_model': 'MacBookPro16,2',
     'physical_memory': '17179869184'},
    {'cpu_brand': 'Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz',
     'cpu_logical_cores': '16',
     'cpu_physical_cores': '8',
     'cpu_subtype': 'Intel x86-64h Haswell',
     'cpu_type': 'x86_64h',
     'hardware_model': 'MacBookPro16,1',
     'physical_memory': '34359738368'},
    {'cpu_brand': 'Intel(R) Core(TM) i5-8210Y CPU @ 1.60GHz',
     'cpu_logical_cores': '4',
     'cpu_physical_cores': '2',
     'cpu_subtype': 'Intel x86-64h Haswell',
     'cpu_type': 'x86_64h',
     'hardware_model': 'MacBookAir8,2',
     'physical_memory': '17179869184'},
    {'cpu_brand': 'Intel(R) Core(TM) i5-1030NG7 CPU @ 1.10GHz',
     'cpu_logical_cores': '8',
     'cpu_physical_cores': '4',
     'cpu_subtype': 'Intel x86-64h Haswell',
     'cpu_type': 'x86_64h',
     'hardware_model': 'MacBookAir9,1',
     'physical_memory': '17179869184'},
    {'cpu_brand': 'Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz',
     'cpu_logical_cores': '8',
     'cpu_physical_cores': '4',
     'cpu_subtype': 'Intel x86-64h Haswell',
     'cpu_type': 'x86_64h',
     'hardware_model': 'MacBookPro15,2',
     'physical_memory': '17179869184'},
    {'cpu_brand': 'Intel(R) Core(TM) i5-8259U CPU @ 2.30GHz',
     'cpu_logical_cores': '8',
     'cpu_physical_cores': '4',
     'cpu_subtype': 'Intel x86-64h Haswell',
     'cpu_type': 'x86_64h',
     'hardware_model': 'MacBookPro15,2',
     'physical_memory': '17179869184'},
    {'cpu_brand': 'Apple M1 Max',
     'cpu_logical_cores': '10',
     'cpu_physical_cores': '10',
     'cpu_subtype': 'ARM64E',
     'cpu_type': 'arm64e',
     'hardware_model': 'MacBook Pro (16-inch, 2021)',
     'physical_memory': '68719476736'},
    {'cpu_brand': 'Apple M1 Pro',
     'cpu_logical_cores': '8',
     'cpu_physical_cores': '8',
     'cpu_subtype': 'ARM64E',
     'cpu_type': 'arm64e',
     'hardware_model': 'MacBook Pro (14-inch, 2021)',
     'physical_memory': '34359738368'},
    {'cpu_brand': 'Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz',
     'cpu_logical_cores': '12',
     'cpu_physical_cores': '6',
     'cpu_subtype': 'Intel x86-64h Haswell',
     'cpu_type': 'x86_64h',
     'hardware_model': 'MacBookPro15,1',
     'physical_memory': '34359738368'},
]

OS_VERSIONS = [
    (12, 3, 1, "macOS", "21E258"),
    (12, 2, 1, "macOS", "21D62"),
    (11, 6, 5, "macOS", "20G527"),
    (11, 6, 0, "macOS", "20G165"),
]

FIREFOX_CHOICES = [
    ("10022.4.19", "100.0"),
    ("9922.4.11", "99.0.1"),
    ("9922.3.30", "99.0"),
]


def make_random_word_function():
    with open("/usr/share/dict/words", "r", encoding="utf-8") as f:
        word_list = list(set(w.strip().lower() for w in f.readlines() if w.strip() and len(w) > 3))

    def random_word_function():
        return random.choice(word_list)

    return random_word_function


def random_serial_number(prefix=""):
    return (prefix
            + random.choice(string.ascii_uppercase)
            + "".join(random.sample(string.ascii_uppercase + string.digits, max(0, 9 - len(prefix))))
            + "".join(random.sample(string.ascii_uppercase, 2)))


def random_uuid():
    return str(uuid_mod.uuid4()).upper()


def random_os_version(cpu_type):
    choices = OS_VERSIONS
    if "arm" in cpu_type.lower():
        choices = [t for t in choices if t[0] >= 12]
    os_version_t = random.choice(choices)
    os_version = dict(zip(("major", "minor", "patch", "name", "build"), os_version_t))
    os_version["table_name"] = "os_version"
    return os_version


def random_system_info(computer_name, serial_number):
    system_info = random.choice(SYSTEM_INFOS)
    system_info["computer_name"] = computer_name
    system_info["hardware_serial"] = serial_number
    system_info["table_name"] = "system_info"
    return system_info


def random_firefox_version():
    version, version_str = random.choice(FIREFOX_CHOICES)
    return {
        "bundle_id": "org.mozilla.firefox",
        "bundle_name": "Firefox",
        "bundle_version": version,
        "bundle_version_str": version_str,
        "bundle_path": "/Applications/Firefox.app",
        "table_name": "apps"
    }


def random_inventory_result(node_key, computer_name, serial_number, uuid, osquery_version):
    system_info = random_system_info(computer_name, serial_number)
    os_version = random_os_version(system_info["cpu_type"])
    app = random_firefox_version()
    return {
        "node_key": node_key,
        "log_type": "result",
        "action": "snapshot",
        "data": [
            {"snapshot": [
                system_info,
                os_version,
                app,
             ],
             "hostIdentifier": serial_number,
             "calendarTime": "",
             "unixTime": 0,
             "epoch": 0,
             "counter": 0,
             "numerics": False,
             "name": "ztl-inv",
             "decorations": {
                 "serial_number": serial_number,
                 "version": osquery_version,
             }}
        ]
    }


def enroll(base_url, enrollment_secret, computer_name, serial_number, uuid, osquery_version):
    enroll_payload = {
        "host_identifier": computer_name,
        "enroll_secret": enrollment_secret,
        "platform_type": "21",
        "host_details": {"system_info": {"hardware_serial": serial_number,
                                         "uuid": uuid},
                         "osquery_info": {"version": osquery_version}},
    }
    response = requests.post(f"{base_url}/osquery/enroll",
                             json=enroll_payload,
                             headers={'user-agent': f"osquery/{osquery_version}"})
    response.raise_for_status()
    return response.json()["node_key"]


def post_inventory_result(base_url, node_key, computer_name, serial_number, uuid, osquery_version):
    inventory_result = random_inventory_result(node_key, computer_name, serial_number, uuid, osquery_version)
    response = requests.post(f"{base_url}/osquery/log",
                             json=inventory_result,
                             headers={'user-agent': f"osquery/{osquery_version}"})
    response.raise_for_status()


def iter_machines(num=10, prefix=""):
    random_word_function = make_random_word_function()
    for i in range(num):
        yield ("-".join(random_word_function() for _ in range(3)),
               random_serial_number(prefix),
               random_uuid())


if __name__ == "__main__":
    import sys
    base_url, enrollment_secret = sys.argv[1:]
    osquery_version = "5.2.2"
    for computer_name, serial_number, uuid in iter_machines(2000, prefix="DEMO"):
        print(computer_name, serial_number, uuid)
        node_key = enroll(base_url, enrollment_secret, computer_name, serial_number, uuid, osquery_version)
        print("Enrollment OK")
        post_inventory_result(base_url, node_key, computer_name, serial_number, uuid, osquery_version)
        print("Inventory OK")
