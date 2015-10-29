from datetime import datetime
import json
from dateutil import parser
import redis

__all__ = ['BaseInventory', 'InventoryError']


class InventoryError(Exception):
    pass


class BaseInventory(object):
    MACHINE_D_DT_FIELDS = ['last_contact_at', 'last_report_at', 'created_at', 'synced_at', 'trashed_at']

    def __init__(self, config_d):
        self._r = redis.Redis(host=config_d.get('redis_host', 'localhost'),
                              port=config_d.get('redis_port', 6379),
                              db=config_d.get('redis_db', 0))
        if not hasattr(self, 'name'):
            self.name = self.__module__.split('.')[-1]

    # Redis storage with serialization / deserialization
    def _get_serializable_machine_d_copy(self, machine_d):
        machine_d = machine_d.copy()
        for fn in self.MACHINE_D_DT_FIELDS:
            val = machine_d.get(fn, None)
            if val:
                machine_d[fn] = val.isoformat()
        return machine_d

    def _redis_all_serial_number_key(self):
        return "MACALLSER"

    def _redis_all_active_serial_number_key(self):
        return "MACALLACTSER"

    def _redis_key_from_serial_number(self, serial_number):
        return "MACSER_{}".format(serial_number).encode('utf-8')

    def _deserialize_machine_d(self, data):
        machine_d = json.loads(data.decode('utf-8'))
        for fn in self.MACHINE_D_DT_FIELDS:
            val = machine_d.get(fn, None)
            if val:
                machine_d[fn] = parser.parse(val)
        return machine_d

    def _redis_mget(self, msn_list):
        keys = [self._redis_key_from_serial_number(msn) for msn in msn_list]
        for data in self._r.mget(keys):
            yield self._deserialize_machine_d(data)

    def _redis_get(self, msn):
        mrk = self._redis_key_from_serial_number(msn)
        data = self._r.get(mrk)
        if data:
            return self._deserialize_machine_d(data)

    def _redis_set(self, msn, machine_d):
        mrk = self._redis_key_from_serial_number(msn)
        machine_d = self._get_serializable_machine_d_copy(machine_d)
        p = self._r.pipeline()
        p.set(mrk, json.dumps(machine_d).encode('utf-8'))
        if machine_d.get('trashed_at'):
            p.srem(self._redis_all_active_serial_number_key(), msn)
        else:
            p.sadd(self._redis_all_active_serial_number_key(), msn)
        p.sadd(self._redis_all_serial_number_key(), msn)
        p.execute()

    # Inv # and links
    def _inv_reference_key(self):
        return "_{}_#".format(self.name)

    def _get_inv_link(self, md):
        return None

    def _add_links_to_machine_d(self, md):
        if not md:
            return
        links = {}
        inv_link = self._get_inv_link(md)
        if inv_link:
            links['inventory'] = {'link': inv_link,
                                  'name': self.name}
        md['_links'] = links

    def get_machines(self):
        return self._get_machines()

    # inventory API
    def sync(self):
        msn_list = []
        for machine_d in self._get_machines():
            s_machine_d = self._get_serializable_machine_d_copy(machine_d)
            self._add_links_to_machine_d(s_machine_d)
            msn = machine_d['serial_number']
            msn_list.append(msn)
            old_d = self._redis_get(msn)
            if old_d is None or old_d.get('trashed_at', None):
                # NEW MACHINE
                machine_d['created_at'] = datetime.utcnow()
                machine_d['synced_at'] = datetime.utcnow()
                self._redis_set(msn, machine_d)
                yield s_machine_d, {'action': 'added'}
            else:
                # UPDATE ?
                diff_d = {}
                for key, val in machine_d.items():
                    if old_d.get(key, None) != val:
                        diff_d[key] = val
                machine_d['created_at'] = old_d['created_at']
                machine_d['synced_at'] = datetime.utcnow()
                self._redis_set(msn, machine_d)
                if diff_d:
                    yield s_machine_d, {'action': 'changed',
                                        'diff': self._get_serializable_machine_d_copy(diff_d)}
        for msn in self._r.smembers(self._redis_all_serial_number_key()):
            msn = msn.decode('utf-8')
            if msn not in msn_list:
                machine_d = self._redis_get(msn)
                if not machine_d.get('trashed_at'):
                    machine_d['trashed_at'] = datetime.utcnow()
                    self._redis_set(msn, machine_d)
                    s_machine_d = self._get_serializable_machine_d_copy(machine_d)
                    self._add_links_to_machine_d(s_machine_d)
                    yield s_machine_d, {'action': 'removed'}

    def machines(self):
        msn_list = self._r.smembers(self._redis_all_active_serial_number_key())
        if msn_list:
            l = []
            for md in self._redis_mget([msn.decode('utf-8') for msn in msn_list]):
                self._add_links_to_machine_d(md)
                l.append(md)
            return l
        else:
            return []

    def machine(self, msn):
        md = self._redis_get(msn)
        self._add_links_to_machine_d(md)
        return md

    def serializable_machine(self, msn):
        md = self._redis_get(msn)
        if not md:
            raise KeyError
        smd = self._get_serializable_machine_d_copy(md)
        self._add_links_to_machine_d(smd)
        return smd

    # Metrics
    def _osx_apps_gauges(self):
        c = {}
        for machine in self.machines():
            for name, version in machine.get('osx_apps', []):
                key = frozenset([('name', name), ('version', version)])
                c[key] = c.setdefault(key, 0) + 1
        return c

    def _os_gauges(self):
        c = {}
        for machine in self.machines():
            key = frozenset([(attr, machine['os_{}'.format(attr)]) for attr in ['name', 'version', 'build']])
            c[key] = c.setdefault(key, 0) + 1
        return c

    def metrics(self):
        return [{'name': 'zentral_inventory_osx_apps_sum',
                 'help_text': 'Zentral inventory OSX apps versions',
                 'gauges': self._osx_apps_gauges()},
                {'name': 'zentral_inventory_os_sum',
                 'help_text': 'Zentral inventory OS versions',
                 'gauges': self._os_gauges()}]
