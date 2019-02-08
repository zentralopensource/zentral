from dateutil import parser
import logging
import requests
from requests.packages.urllib3.util import Retry
from .base import BaseInventory

logger = logging.getLogger('zentral.contrib.inventory.backends.filewave')


class InventoryClient(BaseInventory):
    source_config_secret_attributes = ['api_key']
    MACHINE_QUERY = {
        "name": "Zentral full inventory",
        "main_component": "DesktopClient",
        "criteria": {
            "logic": "one",
            "expressions": [
                {"column": "type", "operator": "is", "component": "OperatingSystem", "qualifier": "macOS"},
                {"column": "type", "operator": "is", "component": "OperatingSystem", "qualifier": "WIN"},
            ]
        },
        "fields": [
            {"component": "DesktopClient", "column": "filewave_id"},
            {"component": "DesktopClient", "column": "serial_number"},
            {"component": "DesktopClient", "column": "last_check_in"},
            {"component": "OperatingSystem", "column": "name"},
            {"component": "OperatingSystem", "column": "type"},
            {"component": "OperatingSystem", "column": "version"},
            {"component": "OperatingSystem", "column": "build"},
            {"component": "DesktopClient", "column": "device_name"},
            {"component": "DesktopClient", "column": "device_product_name"},
            {"component": "DesktopClient", "column": "cpu_type"},
            {"component": "DesktopClient", "column": "cpu_count"},
            {"component": "DesktopClient", "column": "ram_size"},
            {"component": "NetworkInterface", "column": "interface_name"},
            {"component": "NetworkInterface", "column": "mac_address"},
            {"component": "NetworkAddress", "column": "ip_address"},
            {"component": "Fileset", "column": "fileset_id"},
            {"component": "Fileset", "column": "name"},
            {"component": "Fileset", "column": "version"},
        ]
    }
    MACHINE_FIELDS = [
        "filewave_id",
        "serial_number",
        "last_check_in",
        "os_name",
        "os_type",
        "os_version",
        "os_build",
        "computer_name",
        "hardware_model",
        "cpu_type",
        "cpu_logical_cores",
        "physical_memory",
        "interface",
        "mac",
        "address",
        "fileset_id",
        "fileset_name",
        "fileset_version"
    ]

    MACHINE_APPS_QUERY = {
        "name": "Zentral temporary machine apps",
        "main_component": "Application",
        "criteria": {
            "logic": "all",
            "expressions": [
                {"column": "serial_number", "operator": "is", "component": "DesktopClient", "qualifier": None},
            ]
        },
        "fields": [
            {"component": "Application", "column": "name"},
            {"component": "Application", "column": "version"},
            {"component": "Application", "column": "short_version"},
            {"component": "Application", "column": "path"},
            {"component": "Application", "column": "product_id"},
        ]
    }
    MACHINE_APPS_FIELDS = [
        "name",
        "version",
        "short_version",
        "path",
        "product_id",
    ]

    def __init__(self, config_d):
        super().__init__(config_d)
        self.base_url = config_d['base_url']
        self.api_key = config_d['api_key']
        self.verify_tls = config_d.get('verify_tls', True)
        self.base_api_url = '{}/api/v1'.format(self.base_url)
        # requests session setup
        self.session = requests.Session()
        if not self.verify_tls:
            self.session.verify = False
        self.session.headers.update({'user-agent': 'zentral/0.0.1',
                                     'accept': 'application/json',
                                     'authorization': self.api_key})
        max_retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        self.session.mount(self.base_api_url,
                           requests.adapters.HTTPAdapter(max_retries=max_retries))

    def get_machine_query(self):
        r = self.session.get("{}/query/".format(self.base_api_url))
        r.raise_for_status()
        for query in r.json():
            if query["name"] == self.MACHINE_QUERY["name"]:
                r = self.session.get("{}/query/{}".format(self.base_api_url, query["id"]))
                r.raise_for_status()
                return r.json()

    def get_or_update_machine_query(self):
        query = self.get_machine_query()
        if query:
            query_id = query["id"]
            query_ok = all(query.get(k) == v for k, v in self.MACHINE_QUERY.items())
            if not query_ok:
                logger.warning("Delete stale query %s", query_id)
                r = self.session.delete("{}/query/{}".format(self.base_api_url, query_id))
                r.raise_for_status()
            else:
                return query_id
        logger.warning("Create new query")
        r = self.session.post("{}/query/".format(self.base_api_url), json=self.MACHINE_QUERY)
        r.raise_for_status()
        query_id = r.json()["id"]
        return query_id

    def execute_machine_query(self):
        query_id = self.get_or_update_machine_query()
        r = self.session.get("{}/query_result/{}".format(self.base_api_url, query_id))
        r.raise_for_status()
        return r.json()["values"]

    def execute_machine_apps_query(self, serial_number):
        query = self.MACHINE_APPS_QUERY
        query["criteria"]["expressions"][0]["qualifier"] = serial_number
        r = self.session.post("{}/query/".format(self.base_api_url), json=query)
        r.raise_for_status()
        query_id = r.json()["id"]
        r = self.session.get("{}/query_result/{}".format(self.base_api_url, query_id))
        r.raise_for_status()
        values = r.json()["values"]
        r = self.session.delete("{}/query/{}".format(self.base_api_url, query_id))
        r.raise_for_status()
        return values

    def get_machines(self):
        trees = {}
        for t in self.execute_machine_query():
            result = dict(zip(self.MACHINE_FIELDS, t))
            serial_number = result["serial_number"]
            if serial_number not in trees:
                tree = {"serial_number": serial_number,
                        "reference": result["filewave_id"]}
                # os_version
                os_version = dict(zip(("major", "minor", "patch"),
                                      (int(i) for i in (result["os_version"] or "").split("."))))
                if result["os_name"]:
                    os_version["name"] = result["os_name"].split()[0]
                if result["os_build"]:
                    os_version["build"] = result["os_build"]
                if os_version:
                    tree["os_version"] = os_version
                # system info
                system_info = dict((t, result[t])
                                   for t in ("computer_name", "hardware_model", "cpu_type")
                                   if result[t])
                for t in ("cpu_logical_cores", "physical_memory"):
                    try:
                        v = int(result[t])
                    except (TypeError, ValueError):
                        pass
                    else:
                        if v > 0:
                            system_info[t] = v
                if system_info:
                    tree["system_info"] = system_info
                if result["os_type"] == "OSX":
                    osx_app_instances = []
                    for at in self.execute_machine_apps_query(serial_number):
                        aresult = dict(zip(self.MACHINE_APPS_FIELDS, at))
                        app = {"bundle_name": aresult["name"]}
                        if aresult["product_id"]:
                            app["bundle_id"] = aresult["product_id"]
                        if aresult["short_version"]:
                            app["bundle_version_str"] = aresult["short_version"]
                            if aresult["version"]:
                                app["bundle_version"] = aresult["version"]
                        elif aresult["version"]:
                            app["bundle_version_str"] = aresult["version"]
                        osx_app_instances.append({"bundle_path": aresult["path"],
                                                  "app": app})
                    if osx_app_instances:
                        tree["osx_app_instances"] = osx_app_instances
                trees[serial_number] = tree
            else:
                tree = trees[serial_number]
            # network interface
            network_interface = dict((t, result[t])
                                     for t in ("interface", "mac", "address")
                                     if result[t])
            if network_interface and "address" in network_interface:
                tree_network_interfaces = tree.setdefault("network_interfaces", [])
                if network_interface not in tree_network_interfaces:
                    tree_network_interfaces.append(network_interface)
            # last check in
            last_check_in = result.get('last_check_in')
            if last_check_in:
                last_check_in = parser.parse(last_check_in)
                last_seen = tree.get('last_seen')
                if not last_seen or last_seen < last_check_in:
                    tree['last_seen'] = last_check_in

        yield from trees.values()
