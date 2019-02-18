import random
import requests
import string
import uuid as uuid_mod


model_identifiers = {
    'PowerBook': [
        (1, 1),
        (2, 1), (2, 2),
        (3, 1), (3, 2), (3, 3), (3, 4), (3, 5),
        (4, 1), (4, 2), (4, 3),
        (5, 1), (5, 2), (5, 3), (5, 4), (5, 5), (5, 6), (5, 7), (5, 8), (5, 9),
        (6, 1), (6, 2), (6, 3), (6, 4), (6, 5), (6, 7), (6, 8)
    ],
    'MacBookAir': [
        (1, 1),
        (2, 1),
        (3, 1), (3, 2),
        (4, 1), (4, 2),
        (5, 1), (5, 2),
        (6, 1), (6, 2),
        (7, 1), (7, 2),
        (8, 1)
    ],
    'MacBook': [
        (1, 1),
        (2, 1),
        (3, 1),
        (4, 1),
        (5, 1), (5, 2),
        (6, 1),
        (7, 1),
        (8, 1),
        (9, 1),
        (10, 1)
    ],
    'PowerMac': [
        (1, 1), (1, 2),
        (2, 1), (2, 2),
        (3, 1), (3, 3), (3, 4), (3, 5), (3, 6),
        (4, 1), (4, 2), (4, 4), (4, 5),
        (5, 1),
        (6, 1), (6, 3), (6, 4),
        (7, 2), (7, 3),
        (8, 1), (8, 2),
        (9, 1),
        (10, 1), (10, 2),
        (11, 2),
        (12, 1)
    ],
    'MacBookPro': [
        (1, 1), (1, 2),
        (2, 1), (2, 2),
        (3, 1),
        (4, 1),
        (5, 1), (5, 2), (5, 3), (5, 4), (5, 5),
        (6, 1), (6, 2),
        (7, 1),
        (8, 1), (8, 2), (8, 3),
        (9, 1), (9, 2),
        (10, 1), (10, 2),
        (11, 1), (11, 2), (11, 3), (11, 4), (11, 5),
        (12, 1),
        (13, 1), (13, 2), (13, 3),
        (14, 1), (14, 2), (14, 3),
        (15, 1), (15, 2)
    ],
    'Macmini': [
        (1, 1), (2, 1), (3, 1), (4, 1),
        (5, 1), (5, 2), (5, 3),
        (6, 1), (6, 2),
        (7, 1),
        (8, 1)
    ], 'iMac': [
        (4, 1), (4, 2),
        (5, 1), (5, 2),
        (6, 1),
        (7, 1), (8, 1), (9, 1), (10, 1),
        (11, 1), (11, 2), (11, 3),
        (12, 1), (12, 2),
        (13, 1), (13, 2),
        (14, 1), (14, 2), (14, 3), (14, 4),
        (15, 1),
        (16, 1), (16, 2),
        (17, 1),
        (18, 1), (18, 2), (18, 3)
    ],
    'MacPro': [
        (2, 1), (3, 1), (4, 1), (5, 1), (6, 1)
    ],
    'Xserve': [
        (1, 1), (2, 1), (3, 1)
    ],
    'RackMac': [
        (1, 1), (1, 2), (3, 1)
    ],
    'iMacPro': [
        (1, 1)
    ]
}


def make_random_word_function():
    with open("/usr/share/dict/words", "r", encoding="utf-8") as f:
        word_list = list(set(w.strip().lower() for w in f.readlines() if w.strip()))

    def random_word_function():
        return random.choice(word_list)

    return random_word_function


def random_serial_number():
    return (random.choice(string.ascii_uppercase)
            + "".join(random.sample(string.ascii_uppercase + string.digits, 9))
            + "".join(random.sample(string.ascii_uppercase, 2)))


def random_uuid():
    return str(uuid_mod.uuid4()).upper()


def random_os_version():
    major = 10
    minor = random.choices([9, 10, 11, 12, 13, 14], [1, 2, 4, 8, 16, 32])[0]
    patch = random.randint(1, 3)
    return {"major": major,
            "minor": minor,
            "patch": patch,
            "name": "Mac OS X",
            "build": "".join(random.sample(string.ascii_uppercase + string.digits, 5))}


def random_model_identifier():
    family = random.choices(
        ["MacBookAir", "MacBook", "PowerMac", "MacBookPro", "Macmini", "iMac", "MacPro", "iMacPro"],
        [10, 2, 2, 100, 50, 100, 20, 20]
    )[0]
    family_model_identifiers = model_identifiers.get(family)
    major, minor = random.choices(
        family_model_identifiers,
        (2**i for i in range(len(family_model_identifiers)))
    )[0]
    return f"{family}{major},{minor}"


def random_system_info(computer_name, serial_number, uuid):
    return {
        "computer_name": computer_name,
        "hostname": f"{computer_name}.localhost",
        "cpu_brand": "Intel(R) Core(TM) i7-4578U CPU @ 3.00GHz",
        "cpu_logical_cores": "4",
        "cpu_physical_cores": "2",
        "cpu_subtype": "Intel x86-64h Haswell",
        "cpu_type": "x86_64h",
        "hardware_model": random_model_identifier(),
        "hardware_serial": serial_number,
        "physical_memory": "17179869184",
    }


def random_firefox_version():
    major = random.choices([63, 64, 65, 66, 67], [5, 10, 70, 8, 7])[0]
    return {
        "bundle_id": "org.mozilla.firefox",
        "bundle_name": "Firefox",
        "bundle_version": f"{major}18.12.6",
        "bundle_version_str": f"{major}.0",
        "bundle_path": "/Applications/Firefox.app"
    }


def random_inventory_payload(node_key, computer_name, serial_number, uuid):
    os_version = random_os_version()
    os_version["table_name"] = "os_version"
    system_info = random_system_info(computer_name, serial_number, uuid)
    system_info["table_name"] = "system_info"
    apps = random_firefox_version()
    apps["table_name"] = "apps"
    return {
        "queries": {
            "__zentral_distributed_inventory_query_apps": [apps],
            "__zentral_distributed_inventory_query_os_version": [os_version],
            "__zentral_distributed_inventory_query_system_info": [system_info],
            "__zentral_distributed_inventory_query_uptime": [{
                "table_name": "uptime",
                "total_seconds": str(random.randint(62, 24*3600*100))
            }]
        },
        "statuses": {
            "__zentral_distributed_inventory_query_apps": 0,
            # "__zentral_distributed_inventory_query_network_interface": 0,
            "__zentral_distributed_inventory_query_os_version": 0,
            "__zentral_distributed_inventory_query_system_info": 0,
            "__zentral_distributed_inventory_query_uptime": 0
        },
        "node_key": node_key,
    }


def enroll(computer_name, serial_number, uuid, ca_cert):
    enroll_payload = {
        "host_identifier": computer_name,
        "enroll_secret": "tmYA0Il53Z6YcEvGONdylvBrloKKYG8MB74Ktn36T3T9SONxxEo7NLfLZ4Jk2lEz",
        "host_details": {"system_info": {"hardware_serial": serial_number,
                                         "uuid": uuid}}
    }
    response = requests.post("https://zentral/osquery/enroll", json=enroll_payload, verify=ca_cert)
    response.raise_for_status()
    return response.json()["node_key"]


def post_inventory_distributed_query(node_key, computer_name, serial_number, uuid, ca_cert):
    inventory_payload = random_inventory_payload(node_key, computer_name, serial_number, uuid)
    response = requests.post("https://zentral/osquery/distributed/write", json=inventory_payload, verify=ca_cert)
    response.raise_for_status()


def iter_machines(num=10):
    random_word_function = make_random_word_function()
    for i in range(num):
        yield random_word_function(), random_serial_number(), random_uuid()


if __name__ == "__main__":
    import sys
    ca_cert = sys.argv[1]
    for computer_name, serial_number, uuid in iter_machines(100):
        print(computer_name, serial_number, uuid)
        node_key = enroll(computer_name, serial_number, uuid, ca_cert)
        print("Enrollment OK")
        post_inventory_distributed_query(node_key, computer_name, serial_number, uuid, ca_cert)
        print("Inventory OK")
