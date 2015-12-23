import logging
import re
import requests
from .base import BaseInventory, InventoryError

logger = logging.getLogger('zentral.contrib.inventory.backends.watchman')

OS_VERSION_RE = re.compile(r'^(?P<name>.*) (?P<major>[0-9]{1,3})\.'
                           '(?P<minor>[0-9]{1,3})(?:\.'
                           '(?P<patch>[0-9]{1,3}))?(?: \((?P<build>.*)\))?$')
INSTALLED_RAM_RE = re.compile(r'^(?P<val>[0-9\.]+) (?P<unit>(?:GB|kB))$')
PROCESSOR_RE = re.compile(r'(?P<brand>.*) \((?P<cpu_logical_cores>[0-9]+) core '
                          '(?P<cpu_physical_cores>[0-9]+) processor\)$')


class InventoryClient(BaseInventory):
    def __init__(self, config_d):
        super(InventoryClient, self).__init__(config_d)
        self.base_url = 'https://%(account)s.monitoringclient.com' % config_d
        self.base_api_url = '{}/v2.2'.format(self.base_url)
        self.api_key = config_d['api_key']

    def _make_get_query(self, path, **params):
        url = "%s%s" % (self.base_api_url, path)
        params['api_key'] = self.api_key
        headers = {'user-agent': 'zentral/0.0.1',
                   'accept': 'application/json'}
        r = requests.get(url, headers=headers, params=params)
        if r.status_code != requests.codes.ok:
            raise InventoryError()
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

    def _group_machine_links_from_plugin_id(self, pid):
        ll = []
        for anchor_text, url_tmpl in (('Plugin History',
                                       '{}/computers/%MACHINE_SNAPSHOT_REFERENCE%/{}/history'),):
            ll.append({'anchor_text': anchor_text,
                       'url': url_tmpl.format(self.base_url, pid)})
        return ll

    def get_machines(self):
        group_cache = {g.pop('id'): g for g in self._groups()}
        for c in self._computers():
            machine_id = c.pop('watchman_id')
            serial_number = c.pop('serial_number')
            if " " in serial_number.strip():
                logger.info("Computer %s w/o valid serial number", machine_id)
                continue

            # serial number, reference
            ct = {'reference': str(machine_id),
                  'links': self._machine_links_from_id(machine_id),
                  'machine': {'serial_number': serial_number}}

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
                    pid = plugin_result['id']
                    groups.append({'name': "{} - Warning".format(plugin_result['name']),
                                   'reference': pid,
                                   'machine_links': self._group_machine_links_from_plugin_id(pid)})
            if groups:
                ct['groups'] = groups

            # os version
            m = OS_VERSION_RE.match(c['os_version'])
            if m:
                os_version = m.groupdict()
                for k in ('major', 'minor', 'patch'):
                    v = os_version.get(k, None)
                    if v:
                        os_version[k] = int(v)
                ct['os_version'] = os_version

            # system info
            system_info = {'computer_name': c['machine_name'],
                           'hardware_model': c['model_identifier'],
                           'cpu_brand': c['processor'],
                           }
            m = INSTALLED_RAM_RE.match(c['installed_ram'])
            if m:
                val, unit = m.groups()
                if "." in val:
                    val = float(val)
                else:
                    val = int(val)
                if unit == "kB":
                    mul = 2 ** 10
                elif unit == "GB":
                    mul = 2 ** 30
                else:
                    raise ValueError('Unknown unit')
                system_info['physical_memory'] = int(val * mul)
            m = PROCESSOR_RE.match(c['processor'])
            if m:
                system_info.update({'cpu_brand': re.sub(r'\s+', ' ', m.group('brand')),
                                    'cpu_logical_cores': int(m.group('cpu_logical_cores')),
                                    'cpu_physical_cores': int(m.group('cpu_physical_cores'))})
            else:
                logger.info('Unknown processor structure "%s"', c['processor'])
                system_info['cpu_brand'] = c['processor']
            ct['system_info'] = system_info

            # teamviewer
            teamviewer_id = c['teamviewer_id']
            if teamviewer_id:
                ct['teamviewer'] = {'teamviewer_id': teamviewer_id,
                                    'release': c['teamviewer_release'],
                                    'unattended': c['teamviewer_unattended']}
            yield ct
