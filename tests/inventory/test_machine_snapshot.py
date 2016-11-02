import copy
from django.test import TestCase
from zentral.contrib.inventory.conf import MACOS
from zentral.contrib.inventory.models import MachineSnapshot
from zentral.utils.mt_models import MTOError


class MachineSnapshotTestCase(TestCase):
    machine = {'serial_number': "GODZILLAKOMMT"}
    os_version = {'name': 'OS X',
                  'major': 10,
                  'minor': 11,
                  'patch': 1}
    os_version2 = dict(os_version, patch=2)
    osx_app = {'bundle_id': 'io.zentral.baller',
               'bundle_name': 'Baller.app',
               'bundle_version': '123',
               'bundle_version_str': '1.2.3'}
    osx_app2 = {'bundle_id': 'io.zentral.hoho',
                'bundle_name': 'HoHo.app',
                'bundle_version': '978',
                'bundle_version_str': '9.7.8'}
    osx_app_instance = {'app': osx_app,
                        'bundle_path': "/Applications/Baller.app",
                        }
    osx_app_instance2 = {'app': osx_app2,
                         'bundle_path': "/Applications/HoHo.app",
                         }
    source = {'module': 'io.zentral.tests',
              'name': 'zentral'}
    machine_snapshot = {'source': source,
                        'machine': machine,
                        'osx_app_instances': []}
    machine_snapshot_source_error = {'source': "raise_error",
                                     'machine': machine,
                                     'os_version': os_version,
                                     'osx_app_instances': [osx_app_instance]}
    machine_snapshot2 = {'source': source,
                         'machine': machine,
                         'os_version': os_version,
                         'osx_app_instances': [osx_app_instance]}
    machine_snapshot3 = {'source': source,
                         'machine': machine,
                         'os_version': os_version,
                         'osx_app_instances': [osx_app_instance, osx_app_instance2]}

    def test_machine_snapshot_commit_create(self):
        tree = copy.deepcopy(self.machine_snapshot)
        ms, created = MachineSnapshot.objects.commit(tree)
        self.assertTrue(created)
        self.assertEqual(ms.machine.serial_number, self.machine["serial_number"])
        self.assertEqual(ms.source.module, "io.zentral.tests")
        self.assertEqual(ms.source.name, "zentral")
        tree = copy.deepcopy(self.machine_snapshot)
        _, created = MachineSnapshot.objects.commit(tree)
        self.assertFalse(created)

    def test_machine_snapshot_commit_source_error(self):
        tree = copy.deepcopy(self.machine_snapshot_source_error)
        with self.assertRaises(MTOError,
                               msg="Field 'source' of MachineSnapshot has "
                                   "many_to_one: True, many_to_many: False"):
            MachineSnapshot.objects.commit(tree)

    def test_machine_snapshot_commit_update(self):
        tree = copy.deepcopy(self.machine_snapshot)
        ms1, created = MachineSnapshot.objects.commit(tree)
        self.assertTrue(created)
        tree = copy.deepcopy(self.machine_snapshot2)
        ms2, created = MachineSnapshot.objects.commit(tree)
        self.assertTrue(created)
        ms1.refresh_from_db()
        self.assertEqual(ms1.mt_next, ms2)
        self.assertEqual(ms2.update_diff(),
                         {"os_version": {"added": self.os_version},
                          "osx_app_instances": {"added": [self.osx_app_instance]},
                          "platform": {"added": MACOS}})  # don't forget platform !!!
        tree = copy.deepcopy(self.machine_snapshot3)
        ms3, created = MachineSnapshot.objects.commit(tree)
        ms1.refresh_from_db()
        ms2.refresh_from_db()
        self.assertEqual(ms1.mt_next, ms2)
        self.assertEqual(ms2.mt_next, ms3)
        self.assertEqual(ms3.update_diff(),
                         {"osx_app_instances": {"added": [self.osx_app_instance2]}})
