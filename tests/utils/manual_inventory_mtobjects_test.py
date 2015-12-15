#!../../venv/bin/python
import os
import sys
zentral_install = os.path.realpath(os.path.join(os.path.dirname(__file__), "../../server"))
sys.path.insert(0, zentral_install)
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
    machine_d = {'serial_number': "GODZILLAKOMMT"}
    os_version = {'name': 'OS X',
                  'major': 10,
                  'minor': 11,
                  'patch': 1}
    os_version2 = dict(os_version, patch=2)
    osx_app_d = {'bundle_id': 'io.zentral.baller',
                 'bundle_name': 'Baller.app',
                 'version': '123',
                 'version_str': '1.2.3'}
    osx_app_d2 = {'bundle_id': 'io.zentral.hoho',
                  'bundle_name': 'HoHo.app',
                  'version': '978',
                  'version_str': '9.7.8'}
    osx_app_d = {'bundle_name': 'Baller.app',
                 'version_str': '1.2.3'}
    osx_app_d2 = {'bundle_name': 'HoHo.app',
                  'version_str': '9.7.8'}
    osx_app_instance_d = {'app': osx_app_d,
                          'bundle_path': "/Applications/Baller.app",
                          }
    osx_app_instance_d2 = {'app': osx_app_d,
                           'bundle_path': "/Applications/HoHo.app",
                           }
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
                           'osx_app_instances': [osx_app_instance_d, osx_app_instance_d2]}
    obj, _ = test_machine_snapshot(machine_snapshot_d)
    obj2, _ = test_machine_snapshot(machine_snapshot_d2)
    # pprint.pprint(obj2.diff(obj))
    obj3, _ = test_machine_snapshot(machine_snapshot_d3)
    # pprint.pprint(obj3.diff(obj2))
    ai = obj3.osx_app_instances.all()[0]
    print(ai.hash(), ai.mt_hash, ai.path, ai.bundle_path)
    ai.path, ai.bundle_path = ai.bundle_path, ai.path
    print(ai.hash(), ai.mt_hash, ai.path, ai.bundle_path)
