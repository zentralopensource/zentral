import logging
from dateutil import parser
from itertools import chain
from urllib.parse import urlencode
import requests
from requests.packages.urllib3.util import Retry
from zentral.utils.dict import get_nested_val


logger = logging.getLogger('zentral.contrib.puppet.puppetdb_client')


class PuppetDBError(Exception):
    def __init__(self, message):
        self.message = message


class PuppetDBClient(object):
    def __init__(self, config_d):
        self.business_unit_fact_key = config_d.get('business_unit_fact_key')
        self.group_fact_keys = config_d.get('group_fact_keys') or []
        self.extra_fact_keys = config_d.get('extra_fact_keys') or []
        self.puppetboard_url = config_d.get('puppetboard_url')

        # prepare requests session with connection settings
        self.puppetdb_url = config_d["puppetdb_url"]
        self.api_base_url = '{}/pdb/query/v4'.format(self.puppetdb_url)
        self.puppetdb_timeout = config_d.get('puppetdb_timeout', 10)
        self.session = requests.Session()
        # headers
        self.session.headers.update({
            'user-agent': 'zentral/0.0.1',
            'content-type': 'application/json',
            'accept': 'application/json',
            'accept-charset': 'utf-8'
        })
        # ca
        puppetdb_ca = config_d.get("puppetdb_ca")
        if puppetdb_ca:
            self.session.verify = puppetdb_ca
        # client cert
        cert = config_d.get("puppetdb_cert")
        key = config_d.get("puppetdb_key")
        if cert and key:
            self.session.cert = (cert, key)
        elif cert or key:
            raise PuppetDBError("Incomplete puppetDB configuration")
        # max retries
        max_retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        self.session.mount(
            self.api_base_url,
            requests.adapters.HTTPAdapter(max_retries=max_retries)
        )

    def get_source_d(self):
        return {"module": "zentral.contrib.puppet",
                "name": "puppet",
                "config": {"url": self.puppetdb_url}}

    def get_inventory_d(self, certname):
        url = "{}/inventory?{}".format(self.api_base_url,
                                       urlencode({"query": '["=", "certname", "{}"]'.format(certname)}))
        try:
            r = self.session.get(url, timeout=self.puppetdb_timeout)
        except requests.exceptions.RequestException as e:
            raise PuppetDBError("Node '{}': PuppetDB API error: {}".format(certname, e))
        if r.status_code != requests.codes.ok:
            raise PuppetDBError("Node '{}': PuppetDB API HTTP response status code {}".format(certname, r.status_code))
        try:
            inventory_d = r.json()[0]
        except IndexError:
            raise PuppetDBError("Node '{}': empty response".format(certname))
        if inventory_d.get("certname") != certname:
            raise PuppetDBError("Node '{}': certname not in JSON response".format(certname))
        return inventory_d

    def machine_links_from_certname(self, certname):
        links = []
        if self.puppetboard_url:
            links.append({"anchor_text": "Puppetboard",
                          "url": "{}/node/{}".format(self.puppetboard_url, certname)})
        return links

    def get_machine_d(self, certname):
        inventory_d = self.get_inventory_d(certname)
        # source, reference, last_seen
        ct = {'source': self.get_source_d(),
              'reference': certname,
              'last_seen': parser.parse(inventory_d['timestamp'])}

        # links
        links = self.machine_links_from_certname(certname)
        if links:
            ct['links'] = links

        # puppet node
        puppet_node = {'environment': inventory_d['environment']}

        # trusted facts
        trusted = inventory_d['trusted']
        trusted_facts = {}
        for attr in ('authenticated', 'certname', 'extensions'):
            val = trusted.get(attr)
            if val:
                trusted_facts[attr] = val
        if trusted_facts:
            puppet_node['trusted_facts'] = trusted_facts

        facts = inventory_d['facts']

        # system uptime
        try:
            system_uptime = int(facts["system_uptime"]["seconds"])
        except (KeyError, TypeError, ValueError):
            pass
        else:
            if system_uptime > 0:
                ct['system_uptime'] = system_uptime

        # core facts
        core_facts = {}
        for attr, key in (('aio_agent_version', 'aio_agent_version'),
                          ('augeas_version', 'augeas.version'),
                          ('client_version', 'clientversion'),
                          ('facter_version', 'facterversion'),
                          ('ruby_sitedir', 'ruby.sitedir'),
                          ('ruby_version', 'ruby.version'),
                          ('ruby_platform', 'ruby.platform')):
            val = get_nested_val(facts, key)
            if val:
                core_facts[attr] = val
        if core_facts:
            puppet_node['core_facts'] = core_facts

        # extra facts
        extra_facts = {}
        for key in self.extra_fact_keys:
            val = get_nested_val(facts, key)
            if val:
                extra_facts[key] = val
        if extra_facts:
            puppet_node['extra_facts'] = extra_facts

        if puppet_node:
            ct['puppet_node'] = puppet_node

        # business unit from puppet fact
        if self.business_unit_fact_key:
            business_unit_name = get_nested_val(facts, self.business_unit_fact_key)
            if business_unit_name:
                ct['business_unit'] = {'source': self.get_source_d(),
                                       'reference': business_unit_name,
                                       'name': business_unit_name}

        # groups from puppet facts
        groups = []
        for key in self.group_fact_keys:
            group_name = get_nested_val(facts, key)
            if group_name:
                groups.append({'source': self.get_source_d(),
                               'reference': group_name,
                               'name': group_name})
        if groups:
            ct['groups'] = groups

        # network interfaces
        network_interfaces = []
        for if_name, if_d in facts.get("networking", {}).get("interfaces", {}).items():
            mac = if_d.get("mac")
            if not mac:
                continue
            for binding_d in chain(if_d.get("bindings", []), if_d.get("bindings6", [])):
                network_interface_d = {"interface": if_name,
                                       "mac": mac}
                for attr, key in (("address", "address"),
                                  ("mask", "netmask")):
                    val = binding_d.get(key)
                    if val:
                        network_interface_d[attr] = val
                network_interfaces.append(network_interface_d)
        if network_interfaces:
            ct["network_interfaces"] = network_interfaces

        # system info
        system_info = {}

        # system info > processors
        processors = facts["processors"]
        for attr, key in (("cpu_physical_cores", "physicalcount"),
                          ("cpu_logical_cores", "count")):
            try:
                val = int(processors[key])
            except (KeyError, TypeError, ValueError):
                pass
            else:
                if val:
                    system_info[attr] = val
        processor_models = set(processors.get("models", []))
        if processor_models:
            if len(processor_models) > 1:
                logger.warning("Node {}: more than 1 processor model".format(certname))
            system_info["cpu_brand"] = processor_models.pop()

        # system info > physical memory
        try:
            physical_memory = int(facts["memory"]["system"]["total_bytes"])
        except (KeyError, TypeError, ValueError):
            pass
        else:
            if physical_memory:
                system_info["physical_memory"] = physical_memory

        kernel = facts['kernel']
        if kernel == 'Darwin':
            system_profiler = facts['system_profiler']

            # serial number
            serial_number = system_profiler.get('serial_number')
            if not serial_number:
                raise PuppetDBError("Node '{}', Darwin: no system_profiler>serial_number".format(certname))
            ct['serial_number'] = serial_number

            # OS version
            os_macosx = facts['os']['macosx']
            os_version = dict(zip(('major', 'minor', 'patch'),
                                  (int(p) for p in os_macosx['version']['full'].split("."))))
            os_version['name'] = os_macosx['product']
            os_version['build'] = os_macosx['build']
            ct['os_version'] = os_version

            # system info > hardware model, computer name
            for attr, key in (("hardware_model", "model_identifier"),
                              ("computer_name", "computer_name")):
                val = system_profiler.get(key)
                if val:
                    system_info[attr] = val

        elif kernel == "Linux":
            # serial number
            try:
                ct["serial_number"] = facts["dmi"]["product"]["uuid"]
            except KeyError:
                raise PuppetDBError("Node '{}', Linux: no dmi>product>uuid".format(certname))

            # OS version
            os_version = dict(zip(('major', 'minor', 'patch'),
                                  (int(p) for p in facts['os']['release']['full'].split("."))))
            os_version["name"] = facts['os']['name']
            ct['os_version'] = os_version

            # system info > computer name
            system_info['computer_name'] = facts['hostname']

        else:
            raise PuppetDBError("Node '{}': unknown kernel {}".format(certname, kernel))

        if system_info:
            ct["system_info"] = system_info

        return ct
