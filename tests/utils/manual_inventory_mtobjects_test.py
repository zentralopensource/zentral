#!../../venv/bin/python
import os
import sys
nil_install = os.path.realpath(os.path.join(os.path.dirname(__file__), "../../server"))
sys.path.insert(0, nil_install)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'server.settings')
import django
django.setup()

from zentral.contrib.inventory.models import MachineSnapshot


def test_machine_snapshot(d):
    obj, created = MachineSnapshot.objects.commit(d)
    print(created and "CREATED" or "FOUND",
          obj._meta.object_name, obj.mt_hash)
    import pprint
    pprint.pprint(obj.serialize())
    print("")

if __name__ == "__main__":
    osx_app_d = {'bundle_id': 'io.zentral.baller',
                 'bundle_name': 'Ballard',
                 'version': '24987349',
                 'version_str': '2.49.87'}
    osx_app_instance_d = {'app': osx_app_d,
                          'bundle_path': "/home/flaco",
                          'path': "/home/flaco/test",
                          'sha1': 40 * "3",
                          'sha256': 64 * "4",
                          'type': "x486",
                          'signed_by': None}
    machine_d = {'serial_number': "GODZILLAKOMMT"}
    machine_snapshot_d = {'source': 'io.zentral.tests',
                          'machine': machine_d,
                          'osx_app_instances': [osx_app_instance_d]}
    machine_snapshot_d2 = {'source': 'io.zentral.tests',
                           'machine': machine_d,
                           'osx_app_instances': []}
    test_machine_snapshot(machine_snapshot_d2)
    test_machine_snapshot(machine_snapshot_d)
