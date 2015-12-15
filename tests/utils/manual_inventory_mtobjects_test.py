#!../../venv/bin/python
import os
import sys
nil_install = os.path.realpath(os.path.join(os.path.dirname(__file__), "../../server"))
sys.path.insert(0, nil_install)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'server.settings')
import django
django.setup()

import pprint
from zentral.contrib.inventory.models import MachineSnapshot


def test_machine_snapshot(d):
    obj, created = MachineSnapshot.objects.commit(d)
    print(created and "CREATED" or "FOUND",
          obj._meta.object_name, obj.mt_hash)
    pprint.pprint(obj.serialize())
    print("")
    return obj, created

if __name__ == "__main__":
    osx_app_d = {'bundle_id': 'io.zentral.baller',
                 'bundle_name': 'Ballard',
                 'version': '24987349',
                 'version_str': '2.49.87'}
    os_version = {'name': 'OS X',
                  'major': 10,
                  'minor': 11,
                  'patch': 1}
    os_version2 = dict(os_version, patch=2)
    osx_app_instance_d = {'app': osx_app_d,
                          'bundle_path': "/home/flaco",
                          'path': "/home/flaco/test",
                          'sha1': 40 * "3",
                          'sha256': 64 * "4",
                          'type': "x486",
                          'signed_by': None}
    osx_app_instance_d2 = dict(osx_app_instance_d,
                               app=osx_app_d.copy(),
                               type="x64")
    machine_d = {'serial_number': "GODZILLAKOMMT"}
    machine_snapshot_d = {'source': 'io.zentral.tests',
                          'machine': machine_d,
                          'osx_app_instances': []}
    machine_snapshot_d2 = {'source': 'io.zentral.tests',
                           'machine': machine_d,
                           'os_version': os_version,
                           'osx_app_instances': [osx_app_instance_d]}
    machine_snapshot_d3 = {'source': 'io.zentral.tests',
                           'machine': machine_d,
                           'os_version': os_version,
                           'osx_app_instances': [osx_app_instance_d2]}
    obj, _ = test_machine_snapshot(machine_snapshot_d)
    obj2, _ = test_machine_snapshot(machine_snapshot_d2)
    pprint.pprint(obj2.diff(obj))
    obj3, _ = test_machine_snapshot(machine_snapshot_d3)
    pprint.pprint(obj3.diff(obj2))
