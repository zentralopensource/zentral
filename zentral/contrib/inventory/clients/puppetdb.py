from dateutil import parser
from functools import reduce
import operator
import logging
import requests
from requests.packages.urllib3.util import Retry
from .base import BaseInventory

logger = logging.getLogger('zentral.contrib.inventory.backends.puppetdb')


class InventoryClient(BaseInventory):
    source_config_secret_attributes = ['puppetdb_ssl_key', 'puppetdb_ssl_cert', 'puppetdb_ssl_ca']

    def __init__(self, config_d):
        super().__init__(config_d)
        
        # Settings
        self.puppetdb_business_unit_fact_name = config_d.get('business_unit_fact_name', None)
        self.puppetdb_group_fact_names = config_d.get('group_fact_names', [])
        self.puppetdb_facts = config_d.get('facts', [])
        self.puppetdb_save_full_inventory = config_d.get('full_inventory', False)
        self.puppetdb_puppetboard_enable = config_d.get('puppetboard_enable', False)
        self.puppetdb_puppetboard_url = config_d.get('puppetboard_url', None)
        
        # Connection settings
        self.puppetdb_host = config_d['puppetdb_host']
        self.puppetdb_port = config_d.get('puppetdb_port', 8081)
        self.puppetdb_ssl_ca = config_d.get('puppetdb_ssl_ca', None)
        self.puppetdb_ssl_key = config_d.get('puppetdb_ssl_key', None)
        self.puppetdb_ssl_cert = config_d.get('puppetdb_ssl_cert', None)
        self.puppetdb_timeout = config_d.get('puppetdb_timeout', 10)
        self.puppetdb_protocol = config_d.get('puppetdb_protocol', 'https')
        self.base_url = '{}://{}:{}'.format(self.puppetdb_protocol, self.puppetdb_host, self.puppetdb_port)
        self.api_base_url = '{}/pdb/query/v4'.format(self.base_url)
        self.session = requests.Session()
        self.session.headers.update({
            'user-agent': 'zentral/0.0.1',
            'content-type': 'application/json',
            'accept': 'application/json',
            'accept-charset': 'utf-8'
        })
        max_retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        self.session.mount(
            self.api_base_url,
            requests.adapters.HTTPAdapter(max_retries=max_retries)
        )
        
    def _get_puppetdb_inventory(self):
        url = "%s%s" % (self.api_base_url, '/inventory')
        
        try:
            r = self.session.get(url,
            verify=self.puppetdb_ssl_ca,
            cert=(self.puppetdb_ssl_cert, self.puppetdb_ssl_key),
            timeout=self.puppetdb_timeout)
        except requests.exceptions.RequestException as e:
            raise InventoryError("PuppetDB API error: %s" % str(e))
        if r.status_code != requests.codes.ok:
            raise InventoryError("PuppetDB API HTTP response status code %s" % r.status_code)
        return r.json()
    
    def _machine_links_from_id(self, machine_id):
        return [{"anchor_text": "Puppetboard",
                 "url": "{}/node/{}".format(self.puppetdb_puppetboard_url, machine_id)}]
    
    def _deep_get(self, data_dictionary, key_list):
        try:
            return reduce(operator.getitem, key_list, data_dictionary)
        except:
            return None

    def get_machines(self):
        for node in self._get_puppetdb_inventory():
            facts = node['facts']
            trusted = node['trusted']
            
            # the node cert subject CN
            certname_trusted = trusted['certname']
            ct = {
                'reference': certname_trusted,
            }
            
            # Puppetboard link
            if self.puppetdb_puppetboard_enable:
                ct['links'] = self._machine_links_from_id(certname_trusted)
            
            # Certificate extensions
            extensions = []
            for key, value in trusted.get('extensions', []).items():
                extension = {
                    'extension_key': key,
                    'extension_value': value
                }
                extensions.append(extension)
            
            
            # Puppet facts
            custom_facts = []
            if len(self.puppetdb_facts) > 0:
                for fact_name in self.puppetdb_facts:
                    fact_key_split = fact_name['fact_key'].split(".")
                    fact_key = fact_name['fact_key']
                    fact_value = self._deep_get(facts, fact_key_split)
                    if fact_value:
                        custom_facts.append({
                            'fact_value': fact_value,
                            'fact_key': fact_key,
                            'fact_key_display_name': fact_name['fact_display_name']
                        })
            
            puppetdb_inventory = {
                'certname_trusted': certname_trusted,
                'authenticated': trusted.get('authenticated'),
                'timestamp': node.get('timestamp'),
                'aio_agent_version': facts.get('aio_agent_version'),
                'clientversion': facts.get('clientversion'),
                'extensions': extensions,
                'facts': custom_facts,
                'environment': node.get('environment'),
                'agent_specified_environment': facts.get('agent_specified_environment')
            }
            ct['puppetdb_inventory'] = puppetdb_inventory
            
            # Business unit from puppet fact
            if self.puppetdb_business_unit_fact_name:
                business_unit_name = self._deep_get(facts, self.puppetdb_business_unit_fact_name.split("."))
                if business_unit_name:
                    ct['business_unit'] = {
                        'name': business_unit_name,
                        'reference': business_unit_name
                    }
            
            # Groups from puppet facts
            if len(self.puppetdb_group_fact_names) > 0:
                groups = []
                for group_fact_name in self.puppetdb_group_fact_names:
                    group_fact_names_split = group_fact_name['fact_path'].split(".")
                    group_name = self._deep_get(facts, group_fact_names_split)
                    if group_name:
                        groups.append({ 'name': group_name, 'reference': group_name})
                if len(groups) > 0:
                    ct['groups'] = groups
            
            # macOS facts (Darwin)
            os = facts.get('os')
            os_family = os['family']
            if os_family == 'Darwin':
                system_profiler = facts.get('system_profiler', {})
                
                serial_number = system_profiler.get('serial_number', None)
                if serial_number:
                    ct['serial_number'] = serial_number
                
                # OS version
                os_macosx = os.get('macosx', {})
                os_version_full = os_macosx['version']['full']
                os_product = os_macosx['product']
                os_build = os_macosx['build']
                os_version = dict(zip(('major', 'minor', 'patch'), (int(p) for p in os_version_full.split("."))))
                os_version['name'] = os_product
                os_version['build'] = os_build
                ct['os_version'] = os_version
                
                # System info
                hardware_model = system_profiler.get('model_identifier', 'Unknown')
                computer_name = system_profiler.get('computer_name', 'Unknown')
                processors = facts.get('processors', {})
                processor_models = processors.get('models', [])
                if len(processor_models) > 0:
                    processor_name = processor_models[0]
                sp_processor_name = system_profiler.get('processor_name', 'Unknown')
                
                processor_logical_count = processors.get('count', 0)
                processor_physical_count = processors.get('physicalcount', 0)
                
                memory = facts.get('memory', {})
                system_memory = memory.get('system', {})
                system_memory_total_bytes = system_memory.get('total_bytes', 0)
                
                
                ct['system_info'] = {'computer_name': computer_name,
                                     'hardware_model': hardware_model,
                                     'cpu_brand': sp_processor_name,
                                     'cpu_type': processor_name,
                                     'cpu_logical_cores': processor_logical_count,
                                     'cpu_physical_cores': processor_physical_count,
                                     'physical_memory': system_memory_total_bytes}
            else:
                serial_number = 'N/A'
            
            
            # last seen
            timestamp = node.get('timestamp')
            if timestamp:
                ct['last_seen'] = parser.parse(timestamp)
            
            yield ct
