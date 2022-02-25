import logging
from dateutil import parser
from itertools import chain
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util import Retry
from base.utils import deployment_info
from zentral.utils.dict import get_nested_val
from zentral.utils.ssl import create_client_ssl_context
from zentral.utils.text import shard


logger = logging.getLogger('zentral.contrib.puppet.puppetdb_client')


class PuppetDBError(Exception):
    def __init__(self, message):
        self.message = message


class CustomHTTPAdapter(HTTPAdapter):
    def __init__(self, timeout, certdata, keydata, keydata_password, cadata):
        self.timeout = timeout
        self.ssl_context = create_client_ssl_context(certdata, keydata, keydata_password, cadata)
        super().__init__(
            max_retries=Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        )

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self.ssl_context
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["ssl_context"] = self.ssl_context
        return super().proxy_manager_for(*args, **kwargs)

    def send(self, request, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)


class PuppetDBClient(object):
    def __init__(
        self, business_unit, url,
        group_fact_keys, extra_fact_keys, puppetboard_url,
        deb_packages_shard, programs_shard
    ):
        self.business_unit = business_unit
        self.url = url
        # facts
        self.group_fact_keys = group_fact_keys
        self.extra_fact_keys = extra_fact_keys
        self.puppetboard_url = puppetboard_url
        # packages
        self.deb_packages_shard = deb_packages_shard
        self.programs_shard = programs_shard
        # requests session
        self.session = requests.Session()
        self.session.headers["User-Agent"] = deployment_info.user_agent

    def configure_rbac_auth(self, timeout, rbac_token, ca_chain):
        self.session.headers["X-Authentication"] = rbac_token
        self.session.mount(self.url, CustomHTTPAdapter(timeout, None, None, None, ca_chain))

    def configure_client_cert_auth(self, timeout, cert, key, ca_chain):
        self.session.mount(self.url, CustomHTTPAdapter(timeout, cert, key, None, ca_chain))

    @classmethod
    def from_instance(cls, instance):
        client = cls(
            instance.business_unit,
            instance.url,
            instance.group_fact_keys,
            instance.extra_fact_keys,
            instance.puppetboard_url,
            instance.deb_packages_shard,
            instance.programs_shard
        )
        if instance.cert:
            client.configure_client_cert_auth(
                instance.timeout,
                instance.cert,
                instance.get_key(),
                instance.ca_chain
            )
        else:
            client.configure_rbac_auth(
                instance.timeout,
                instance.get_rbac_token(),
                instance.ca_chain
            )
        return client

    def get_business_unit_d(self):
        return self.business_unit.serialize()

    def get_source_d(self):
        return {"module": "zentral.contrib.puppet",
                "name": "puppet",
                "config": {"url": self.url}}

    def make_request(self, path, certname):
        try:
            r = self.session.get(
                f"{self.url}/pdb/query/v4{path}",
                params={"query": f'["=", "certname", {certname}]'}
            )
        except requests.exceptions.RequestException as e:
            raise PuppetDBError(f"Node '{certname}' {path}: PuppetDB API error: {e}")
        if r.status_code != requests.codes.ok:
            raise PuppetDBError(f"Node '{certname}' {path}: PuppetDB API HTTP response status code {r.status_code}")
        return r.json()

    def get_inventory_d(self, certname):
        resp_json = self.make_request("/inventory", certname)
        try:
            inventory_d = resp_json[0]
        except IndexError:
            raise PuppetDBError(f"Node '{certname}': empty response")
        if inventory_d.get("certname") != certname:
            raise PuppetDBError(f"Node '{certname}': certname not in JSON response")
        return inventory_d

    def iter_certname_packages(self, certname):
        resp_json = self.make_request("/packages", certname)
        if not resp_json:
            logger.warning("Node '%s': no packages found", certname)
            return
        for package in resp_json:
            name = package.get("package_name")
            if not name:
                logger.warning("Node '%s': missing package name", certname)
                continue
            version = package.get("version")
            if not version:
                logger.warning("Node '%s': missing package version", certname)
                continue
            provider = package.get("provider")
            if not provider:
                logger.warning("Node '%s': missing package provider", certname)
                continue
            yield name, version, provider

    def machine_links_from_certname(self, certname):
        links = []
        if self.puppetboard_url:
            links.append({"anchor_text": "Puppetboard",
                          "url": f"{self.puppetboard_url}/node/{certname}"})
        return links

    def add_ct_packages(self, ct, certname):
        serial_number = ct.get("serial_number")
        include_deb_packages = (
            self.deb_packages_shard == 100
            or (self.deb_packages_shard
                and serial_number
                and shard(serial_number, "puppet_deb_packages") < self.deb_packages_shard)
        )
        include_programs = (
            self.programs_shard == 100
            or (self.programs_shard
                and serial_number
                and shard(serial_number, "puppet_programs") < self.programs_shard)
        )
        if not include_deb_packages and not include_programs:
            return
        for name, version, provider in self.iter_certname_packages(certname):
            if provider == "apt" and include_deb_packages:
                deb_package = {"name": name, "version": version}
                deb_packages = ct.setdefault("deb_packages", [])
                if deb_package not in deb_packages:
                    deb_packages.append(deb_package)
            elif provider == "windows" and include_programs:
                program_instance = {"program": {"name": name, "version": version}}
                program_instances = ct.setdefault("program_instances", [])
                if program_instance not in program_instances:
                    program_instances.append(program_instance)

    def get_machine_d(self, certname):
        inventory_d = self.get_inventory_d(certname)
        # source, reference, last_seen
        ct = {'source': self.get_source_d(),
              'reference': certname,
              'last_seen': parser.parse(inventory_d['timestamp']),
              'business_unit': self.get_business_unit_d()}

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
                logger.warning(f"Node {certname}: more than 1 processor model")
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
                raise PuppetDBError(f"Node '{certname}', Darwin: no system_profiler>serial_number")
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
                ct["serial_number"] = facts["serialnumber"]
            except KeyError:
                try:
                    ct["serial_number"] = facts["dmi"]["product"]["uuid"]
                except KeyError:
                    raise PuppetDBError(f"Node '{certname}', Linux: no dmi>product>uuid")

            # OS version
            os_version = dict(zip(('major', 'minor', 'patch'),
                                  (int(p) for p in facts['os']['release']['full'].split("."))))
            os_version["name"] = facts['os']['name']
            ct['os_version'] = os_version

            # system info > computer name
            system_info['computer_name'] = facts['hostname']

        else:
            raise PuppetDBError(f"Node '{certname}': unknown kernel {kernel}")

        if system_info:
            ct["system_info"] = system_info

        self.add_ct_packages(ct, certname)

        return ct
