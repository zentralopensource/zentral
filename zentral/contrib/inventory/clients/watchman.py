from datetime import datetime
import logging
import re
import requests
from requests.packages.urllib3.util import Retry
from .base import BaseInventory, InventoryError

logger = logging.getLogger('zentral.contrib.inventory.backends.watchman')

MAC_VERSION_RE = re.compile(r'^(?P<name>.*) (?P<major>[0-9]{1,3})\.'
                            '(?P<minor>[0-9]{1,3})(?:\.'
                            '(?P<patch>[0-9]{1,3}))?(?: \((?P<build>.*)\))?$')
LINUX_VERSION_RE = re.compile(r'^(?P<name>[^0-9]*) (?P<major>[0-9]{1,3})\.'
                              '(?P<minor>[0-9]{1,3})(?:\.'
                              '(?P<patch>[0-9]{1,3}))?.*$')
WINDOWS_VERSION_RE = re.compile(r'^(?P<name>[^0-9]* (?P<major>[0-9]{1,3})\.'
                                '(?P<minor>[0-9]{1,3}).*)$')
PROCESSOR_RE = re.compile(r'(?P<cpu_brand>.*) \((?:(?P<cpu_physical_cores>[0-9]+) core )?'
                          '(?P<cpus>[0-9]+) processor\)$')


class InventoryClient(BaseInventory):
    source_config_secret_attributes = ['api_key']

    def __init__(self, config_d):
        super(InventoryClient, self).__init__(config_d)
        self.base_url = 'https://%(account)s.monitoringclient.com' % config_d
        self.base_api_url = '{}/v2.5'.format(self.base_url)
        # requests session setup
        self.session = requests.Session()
        self.session.headers.update({'user-agent': 'zentral/0.0.1',
                                     'accept': 'application/json'})
        self.session.params = {'api_key': config_d['api_key']}
        max_retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        self.session.mount(self.base_api_url,
                           requests.adapters.HTTPAdapter(max_retries=max_retries))

    def _make_get_query(self, path, **params):
        url = "%s%s" % (self.base_api_url, path)
        try:
            r = self.session.get(url, params=params)
        except requests.exceptions.RequestException as e:
            raise InventoryError("Watchman API error: %s" % str(e))
        if r.status_code != requests.codes.ok:
            raise InventoryError("Watchman API HTTP response status code %s" % r.status_code)
        return r.json()

    def _make_paginated_get_query(self, path, **params):
        params['page'] = 0
        while True:
            i = 0
            params['page'] += 1
            for r in self._make_get_query(path, **params):
                i += 1
                yield r
            if i < 50:
                break

    def _computers(self):
        return self._make_paginated_get_query('/computers',
                                              **{'expand[]': 'computer.plugin_results'})

    def _groups(self):
        return self._make_paginated_get_query('/groups')

    def _machine_links_from_id(self, machine_id):
        ll = []
        for anchor_text, url_tmpl in (('Inventory', "{}/computers/{}"),):
            ll.append({'anchor_text': anchor_text,
                       'url': url_tmpl.format(self.base_url, machine_id)})
        return ll

    def _business_unit_links_from_group_d(self, group_d):
        ll = []
        for anchor_text, url_tmpl in (('Group', "{}/groups/{}"),):
            ll.append({'anchor_text': anchor_text,
                       'url': url_tmpl.format(self.base_url, group_d['slug'])})
        return ll

    def _group_machine_links_from_plugin_slug(self, slug):
        ll = []
        for anchor_text, url_tmpl in (('Plugin History',
                                       '{}/computers/%MACHINE_SNAPSHOT_REFERENCE%/{}/history'),):
            ll.append({'anchor_text': anchor_text,
                       'url': url_tmpl.format(self.base_url, slug)})
        return ll

    @staticmethod
    def _system_info_update_dict_from_processor(processor):
        cpu_update_dict = {}
        processor = processor.strip()
        m = PROCESSOR_RE.match(processor)
        if m:
            cpu_brand = re.sub(r'\s+', ' ', m.group('cpu_brand'))
            if cpu_brand:
                cpu_update_dict['cpu_brand'] = cpu_brand
            cpu_physical_cores = m.group('cpu_physical_cores')
            if cpu_physical_cores:
                cpu_physical_cores = int(cpu_physical_cores)
                if cpu_physical_cores:
                    cpu_update_dict['cpu_physical_cores'] = cpu_physical_cores
        else:
            logger.info('Unknown processor structure "%s"', processor)
            if processor:
                cpu_update_dict['cpu_brand'] = processor
        return cpu_update_dict

    def get_machines(self):
        group_cache = {g.pop('uid'): g for g in self._groups()}
        machines = {}
        for c in self._computers():
            platform = c.pop('platform')
            machine_id = c.pop('watchman_id')
            serial_number = c.pop('serial_number')
            if c.pop('hidden'):
                logger.warning("Hidden computer %s %s", serial_number, machine_id)
                continue
            created_at = c.pop('created_at')
            if serial_number in machines:
                logger.warning("Computer %s has multiple instances", serial_number)
                if machines[serial_number]['created_at'] > created_at:
                    logger.warning("Instance %s of Computer %s ignored",
                                   machine_id,
                                   serial_number)
                    continue
                else:
                    logger.warning("Instance %s of Computer %s ignored",
                                   machines[serial_number]['machine_id'],
                                   serial_number)
            if platform == 'linux' or platform == 'windows':
                # TODO better!
                serial_number = machine_id
            elif platform == 'mac':
                if " " in serial_number.strip():
                    logger.error("Computer %s w/o valid serial number", machine_id)
                    continue
            else:
                logger.warning("Unknown platform %s for computer %s", platform, machine_id)
                continue

            # serial number, reference
            ct = {'reference': str(machine_id),
                  'links': self._machine_links_from_id(machine_id),
                  'serial_number': serial_number}

            # last seen
            last_report = c.get('last_report')
            if last_report:
                ct['last_seen'] = datetime.utcfromtimestamp(last_report)

            # the unique group is a business unit in zentral
            gid = c['group']
            if gid:
                g = group_cache.get(gid, None)
                if g:
                    ct['business_unit'] = {'name': g['name'],
                                           'reference': gid,
                                           'links': self._business_unit_links_from_group_d(g)}

            # the plugins in status "warning" are used to form groups
            groups = []
            for plugin_result in c.get('plugin_results', []):
                if plugin_result['status'] == 'warning':
                    slug = plugin_result['slug']
                    groups.append({'name': "{} - Warning".format(plugin_result['name']),
                                   'reference': slug,
                                   'machine_links': self._group_machine_links_from_plugin_slug(slug)})
            if groups:
                ct['groups'] = groups

            # os version
            m = None
            if platform == 'mac':
                m = MAC_VERSION_RE.match(c['os_version'])
            elif platform == 'linux':
                m = LINUX_VERSION_RE.match(c['os_version'])
            elif platform == 'windows':
                m = WINDOWS_VERSION_RE.match(c['os_version'])
            if m:
                os_version = m.groupdict()
                for k in ('major', 'minor', 'patch'):
                    v = os_version.get(k)
                    if v:
                        os_version[k] = int(v)
                ct['os_version'] = os_version

            # system info
            system_info = {}
            for attr, si_attr in (('computer_name', 'computer_name'),
                                  ('model_identifier', 'hardware_model'),
                                  ('processor', 'cpu_brand')):
                val = c.get(attr)
                if val:
                    system_info[si_attr] = val
            system_info['physical_memory'] = int(c['ram_installed_in_bytes'])
            system_info.update(self._system_info_update_dict_from_processor(c['processor']))
            ct['system_info'] = system_info

            # network interfaces
            network_interface = {}
            for attr, ni_attr in (('active_mac_address', 'mac'),
                                  ('primary_ip', 'address')):
                value = c.get(attr, None)
                if value:
                    network_interface[ni_attr] = value
            if len(network_interface) == 2:
                network_interface['interface'] = 'primary'
                ct['network_interfaces'] = [network_interface]

            # teamviewer
            teamviewer_id = c['teamviewer_id']
            if teamviewer_id:
                ct['teamviewer'] = {'teamviewer_id': teamviewer_id,
                                    'release': c['teamviewer_release'],
                                    'unattended': c['teamviewer_unattended']}
            machines[serial_number] = {'machine_id': machine_id,
                                       'created_at': created_at,
                                       'commit_tree': ct}
        for machine_d in machines.values():
            yield machine_d['commit_tree']
