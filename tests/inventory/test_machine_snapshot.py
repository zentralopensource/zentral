import copy
from datetime import datetime, timedelta
from dateutil import parser
from django.test import TestCase
from django.utils.timezone import is_aware, make_naive
from zentral.contrib.inventory.conf import DESKTOP, MACOS, SERVER, update_ms_tree_type, VM
from zentral.contrib.inventory.models import (BusinessUnit,
                                              Certificate,
                                              CurrentMachineSnapshot,
                                              MachineSnapshot, MachineSnapshotCommit,
                                              MachineTag,
                                              MetaBusinessUnitTag,
                                              MetaMachine,
                                              Source,
                                              Tag)
from zentral.utils.mt_models import MTOError


class MachineSnapshotTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.serial_number = "GODZILLAKOMMT"
        cls.os_version = {'name': 'OS X',
                          'major': 10,
                          'minor': 11,
                          'patch': 1}
        cls.os_version2 = dict(cls.os_version, patch=2)
        cls.osx_app = {'bundle_id': 'io.zentral.baller',
                       'bundle_name': 'Baller.app',
                       'bundle_version': '123',
                       'bundle_version_str': '1.2.3'}
        cls.osx_app2 = {'bundle_id': 'io.zentral.hoho',
                        'bundle_name': 'HoHo.app',
                        'bundle_version': '978',
                        'bundle_version_str': '9.7.8'}
        cls.certificate = {'common_name': 'Apple Root CA',
                           'organization': 'Apple Inc.',
                           'organizational_unit': 'Apple Certification Authority',
                           'sha_1': '611e5b662c593a08ff58d14ae22452d198df6c60',
                           'sha_256': 'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024',
                           'valid_from': parser.parse('2006/04/25 23:40:36 +0200'),
                           'valid_until': parser.parse('2035/02/09 22:40:36 +0100')}
        cls.osx_app_instance = {'app': cls.osx_app,
                                'bundle_path': "/Applications/Baller.app",
                                'signed_by': cls.certificate
                                }
        cls.osx_app_instance2 = {'app': cls.osx_app2,
                                 'bundle_path': "/Applications/HoHo.app",
                                 'signed_by': cls.certificate
                                 }
        cls.source = {'module': 'io.zentral.tests',
                      'name': 'zentral'}
        cls.business_unit_tree = {
            "name": "bulle",
            "reference": "bulle 1",
            "source": cls.source
        }
        cls.business_unit, _ = BusinessUnit.objects.commit(cls.business_unit_tree)
        cls.meta_business_unit = cls.business_unit.meta_business_unit
        cls.machine_snapshot = {'source': cls.source,
                                'business_unit': cls.business_unit_tree,
                                'serial_number': cls.serial_number,
                                'osx_app_instances': []}
        cls.machine_snapshot_source_error = {'source': "raise_error",
                                             'serial_number': cls.serial_number,
                                             'os_version': cls.os_version,
                                             'osx_app_instances': [cls.osx_app_instance]}
        cls.machine_snapshot2 = {'source': cls.source,
                                 'business_unit': cls.business_unit_tree,
                                 'serial_number': cls.serial_number,
                                 'os_version': cls.os_version,
                                 'osx_app_instances': [cls.osx_app_instance]}
        cls.machine_snapshot3 = {'source': cls.source,
                                 'business_unit': cls.business_unit_tree,
                                 'serial_number': cls.serial_number,
                                 'os_version': cls.os_version,
                                 'osx_app_instances': [cls.osx_app_instance, cls.osx_app_instance2]}

    def test_machine_snapshot_commit_create(self):
        tree = copy.deepcopy(self.machine_snapshot)
        msc, ms = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertIsInstance(msc, MachineSnapshotCommit)
        self.assertEqual(msc.machine_snapshot, ms)
        self.assertEqual(msc.version, 1)
        self.assertEqual(msc.serial_number, self.serial_number)
        self.assertEqual(ms.serial_number, self.serial_number)
        self.assertEqual(ms.source.module, "io.zentral.tests")
        self.assertEqual(ms.source.name, "zentral")
        self.assertEqual(ms.source, msc.source)
        self.assertEqual(msc.parent, None)
        self.assertEqual(msc.update_diff(), None)
        self.assertEqual(CurrentMachineSnapshot.objects.all().count(), 1)
        cms = CurrentMachineSnapshot.objects.get(serial_number=self.serial_number, source=ms.source)
        self.assertEqual(cms.machine_snapshot, ms)
        tree = copy.deepcopy(self.machine_snapshot)
        msc2, ms2 = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(ms, ms2)
        self.assertEqual(CurrentMachineSnapshot.objects.all().count(), 1)
        cms = CurrentMachineSnapshot.objects.get(serial_number=self.serial_number, source=ms.source)
        self.assertEqual(cms.machine_snapshot, ms)

    def test_machine_snapshot_commit_source_error(self):
        tree = copy.deepcopy(self.machine_snapshot_source_error)
        with self.assertRaises(MTOError,
                               msg="Field 'source' of MachineSnapshot has "
                                   "many_to_one: True, many_to_many: False"):
            MachineSnapshot.objects.commit(tree)

    def test_machine_snapshot_commit_update(self):
        tree = copy.deepcopy(self.machine_snapshot)
        msc1, ms1 = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertIsInstance(msc1, MachineSnapshotCommit)
        tree = copy.deepcopy(self.machine_snapshot2)
        msc2, ms2 = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertIsInstance(msc2, MachineSnapshotCommit)
        self.assertEqual(msc2.parent, msc1)
        self.assertEqual(CurrentMachineSnapshot.objects.all().count(), 1)
        cms = CurrentMachineSnapshot.objects.get(serial_number=self.serial_number, source=ms2.source)
        self.assertEqual(cms.machine_snapshot, ms2)

        def prepare_diff_dict(d):
            for k, v in d.items():
                if isinstance(v, datetime):
                    if is_aware(v):
                        v = make_naive(v)
                    d[k] = v.isoformat()
                elif isinstance(v, dict):
                    prepare_diff_dict(v)
                elif isinstance(v, list):
                    for vi in v:
                        prepare_diff_dict(vi)

        osx_app_instance_diff = copy.deepcopy(self.osx_app_instance)
        prepare_diff_dict(osx_app_instance_diff)
        self.assertEqual(msc2.update_diff(),
                         {"os_version": {"added": self.os_version},
                          "osx_app_instances": {"added": [osx_app_instance_diff]},
                          "last_seen": {"added": msc2.last_seen,
                                        "removed": msc1.last_seen},
                          "platform": {"added": MACOS}})  # don't forget platform !!!
        tree = copy.deepcopy(self.machine_snapshot3)
        msc3, ms3 = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(msc3.parent, msc2)
        self.assertEqual(CurrentMachineSnapshot.objects.all().count(), 1)
        cms = CurrentMachineSnapshot.objects.get(serial_number=self.serial_number, source=ms3.source)
        self.assertEqual(cms.machine_snapshot, ms3)
        osx_app_instance2_diff = copy.deepcopy(self.osx_app_instance2)
        prepare_diff_dict(osx_app_instance2_diff)
        self.assertEqual(msc3.update_diff(),
                         {"last_seen": {"added": msc3.last_seen, "removed": msc2.last_seen},
                          "osx_app_instances": {"added": [osx_app_instance2_diff]}})
        self.assertEqual(ms3.mt_hash, ms3.hash())
        self.assertEqual(Certificate.objects.count(), 1)
        tree = copy.deepcopy(self.machine_snapshot2)
        msc4, ms4 = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(ms4, ms2)
        self.assertEqual(msc4.parent, msc3)
        self.assertEqual(msc4.machine_snapshot, ms2)
        self.assertEqual(CurrentMachineSnapshot.objects.all().count(), 1)
        cms = CurrentMachineSnapshot.objects.get(serial_number=self.serial_number, source=ms4.source)
        self.assertEqual(cms.machine_snapshot, ms2)

    def test_duplicated_subtrees(self):
        tree = copy.deepcopy(self.machine_snapshot3)
        tree["osx_app_instances"].append(copy.deepcopy(self.osx_app_instance2))
        with self.assertRaises(MTOError,
                               msg="Duplicated subtree in key osx_app_instances"):
            MachineSnapshot.objects.commit(tree)

    def test_commit_certificate(self):
        tree = copy.deepcopy(self.certificate)
        cert, created = Certificate.objects.commit(tree)
        cert.refresh_from_db()
        self.assertEqual(cert.hash(), cert.mt_hash)

    def test_source(self):
        tree = copy.deepcopy(self.machine_snapshot3)
        msc, ms = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        tree = copy.deepcopy(self.machine_snapshot3)
        tree["serial_number"] = tree["serial_number"][::-1]
        msc2, ms2 = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(msc2.source, msc.source)
        self.assertEqual(ms2.source, ms.source)
        self.assertEqual([], list(Source.objects.current_machine_group_sources()))
        self.assertEqual([ms.source], list(Source.objects.current_business_unit_sources()))
        self.assertEqual([ms.source], list(Source.objects.current_machine_snapshot_sources()))
        self.assertEqual([ms.source], list(Source.objects.current_macos_apps_sources()))
        for sn in (self.serial_number, ms2.serial_number):
            mm = MetaMachine(sn)
            mm.archive()
        self.assertEqual([], list(Source.objects.current_machine_snapshot_sources()))
        self.assertEqual([], list(Source.objects.current_macos_apps_sources()))

    def test_machine_snapshot_current_platform(self):
        tree = copy.deepcopy(self.machine_snapshot3)
        msc, ms = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(MachineSnapshot.objects.current_platforms(),
                         [(MACOS, "macOS")])

    def test_machine_snapshot_current_type(self):
        tree = copy.deepcopy(self.machine_snapshot3)
        tree["system_info"] = {"hardware_model": "imac"}
        msc, ms = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(MachineSnapshot.objects.current_types(),
                         [(DESKTOP, "Desktop")])

    def test_machine_snapshot_current(self):
        tree = copy.deepcopy(self.machine_snapshot)
        msc, ms = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        tree = copy.deepcopy(self.machine_snapshot2)
        msc2, ms2 = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        tree = copy.deepcopy(self.machine_snapshot3)
        msc3, ms3 = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(MachineSnapshot.objects.count(), 3)
        self.assertEqual(MachineSnapshot.objects.current().count(), 1)
        self.assertEqual(MachineSnapshot.objects.current().get(pk=ms3.id), ms3)
        mm = MetaMachine(self.serial_number)
        mm.archive()
        self.assertEqual(CurrentMachineSnapshot.objects.count(), 0)
        tree = copy.deepcopy(self.machine_snapshot3)
        msc4, ms4 = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(ms3, ms4)
        self.assertEqual(CurrentMachineSnapshot.objects.count(), 1)
        cms = CurrentMachineSnapshot.objects.get(serial_number=self.serial_number)
        self.assertEqual(cms.machine_snapshot, ms3)

    def test_has_recent_source_snapshot(self):
        tree = copy.deepcopy(self.machine_snapshot)
        module = self.source["module"]
        age = 7200
        last_seen = datetime.utcnow() - timedelta(seconds=age)
        tree["last_seen"] = last_seen
        msc, ms = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        mm = MetaMachine(self.serial_number + "e12908e1209")
        self.assertFalse(mm.has_recent_source_snapshot(module, max_age=2*age))
        mm = MetaMachine(self.serial_number)
        self.assertFalse(mm.has_recent_source_snapshot(module + "lkjdelkwd", max_age=2*age))
        self.assertFalse(mm.has_recent_source_snapshot(module))
        self.assertTrue(mm.has_recent_source_snapshot(module, max_age=2*age))
        mm.archive()
        self.assertFalse(mm.has_recent_source_snapshot(module))
        self.assertFalse(mm.has_recent_source_snapshot(module, max_age=2*age))

    def test_meta_machine(self):
        tree = copy.deepcopy(self.machine_snapshot)
        msc, ms = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        tree = copy.deepcopy(self.machine_snapshot2)
        msc2, ms2 = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        tree = copy.deepcopy(self.machine_snapshot3)
        msc3, ms3 = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        mm = MetaMachine(self.serial_number)
        self.assertEqual(mm.serial_number, self.serial_number)
        self.assertEqual(mm.snapshots, [ms3])
        self.assertEqual(mm.platform, MACOS)
        tag1, _ = Tag.objects.get_or_create(name="tag111")
        tag2, _ = Tag.objects.get_or_create(name="tag222")
        MachineTag.objects.create(tag=tag1, serial_number=self.serial_number)
        self.assertEqual((MACOS, None, {self.meta_business_unit.id}, {tag1.id}),
                         mm.get_probe_filtering_values())
        MetaBusinessUnitTag.objects.create(tag=tag2, meta_business_unit=self.meta_business_unit)
        self.assertEqual((MACOS, None, {self.meta_business_unit.id}, {tag1.id, tag2.id}),
                         mm.get_probe_filtering_values())
        mm.archive()
        mm = MetaMachine(self.serial_number)
        self.assertEqual(mm.snapshots, [])
        self.assertEqual(MachineSnapshot.objects.count(), 3)
        self.assertEqual(MachineSnapshotCommit.objects.count(), 3)
        self.assertEqual(CurrentMachineSnapshot.objects.count(), 0)

    def test_machine_name(self):
        tree = {"source": {"module": "godzilla",
                           "name": "test"},
                "serial_number": "yo"}
        msc, ms = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(copy.deepcopy(tree))
        self.assertEqual(ms.get_machine_str(), "yo")
        tree["system_info"] = {"hostname": "hostname yo"}
        msc, ms = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(copy.deepcopy(tree))
        self.assertEqual(ms.get_machine_str(), "hostname yo")
        tree["system_info"] = {"computer_name": "computername yo",
                               "hostname": "hostname yo"}
        msc, ms = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(copy.deepcopy(tree))
        self.assertEqual(ms.get_machine_str(), "computername yo")

    def test_machine_tag(self):
        tree = copy.deepcopy(self.machine_snapshot)
        msc, ms = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        tag = Tag.objects.create(name="tag name")
        self.assertEqual(str(tag), "tag name")
        MachineTag.objects.create(tag=tag, serial_number=self.serial_number)
        self.assertEqual(list(Tag.objects.used_in_inventory()), [(tag, 1)])
        mm = MetaMachine(self.serial_number)
        mm.archive()
        self.assertEqual(list(Tag.objects.used_in_inventory()), [])

    def test_update_ms_tree_type_hardware_model(self):
        tree = {"system_info": {"hardware_model": "IMac"}}
        update_ms_tree_type(tree)
        self.assertEqual(tree.get("type"), DESKTOP)
        tree = {"system_info": {"hardware_model1111": "kjwelkjdwlkej"}}
        self.assertEqual(tree.get("type"), None)

    def test_update_ms_tree_type_network_interface(self):
        tree = {"network_interfaces": [{"mac": "00:1c:42:00:00:08",
                                        "name": "en0",
                                        "address": "192.168.1.17"}]}
        update_ms_tree_type(tree)
        self.assertEqual(tree.get("type"), VM)
        tree = {"system_info": {"hardware_model": "lkqjdwlkjwqd"},
                "network_interfaces": [{"mac": "00:1C:42:00:00:08",
                                        "name": "en0",
                                        "address": "192.168.1.17"}]}
        update_ms_tree_type(tree)
        self.assertEqual(tree.get("type"), VM)
        tree = {"network_interfaces": [{"mac": "38:c9:86:1d:71:ad",
                                        "name": "en0",
                                        "address": "192.168.1.19"},
                                       {"mac": "00:1c:42:00:00:08",
                                        "name": "en0",
                                        "address": "192.168.1.17"}]}
        self.assertEqual(tree.get("type"), None)
        tree = {"network_interfaces": [{"mac": 11,
                                        "name": "en0",
                                        "address": "192.168.1.17"}]}
        update_ms_tree_type(tree)
        self.assertEqual(tree.get("type"), None)
        tree = {"network_interfaces": [{"name": "en0",
                                        "address": "192.168.1.17"}]}
        update_ms_tree_type(tree)
        self.assertEqual(tree.get("type"), None)

    def test_update_ms_tree_type_cpu_brand(self):
        tree = {"system_info": {"hardware_model": "kjwelkjdwlkej",
                                "cpu_brand": "Xeon godz"}}
        update_ms_tree_type(tree)
        self.assertEqual(tree.get("type"), SERVER)
        tree = {"system_info": {"hardware_model": "kjwelkjdwlkej",
                                "cpu_brand": "Godz"}}
        update_ms_tree_type(tree)
        self.assertEqual(tree.get("type"), None)

    def test_last_seen(self):
        tree = copy.deepcopy(self.machine_snapshot)
        last_seen = datetime.utcnow()
        tree["last_seen"] = last_seen
        msc, ms = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(msc.last_seen, last_seen)
        tree = copy.deepcopy(self.machine_snapshot)
        tree["last_seen"] = last_seen
        msc2, ms2 = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(msc2, None)
        tree = copy.deepcopy(self.machine_snapshot)
        last_seen3 = datetime.utcnow()
        tree["last_seen"] = last_seen3
        msc3, ms3 = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(msc3.last_seen, last_seen3)
        self.assertEqual(msc3.parent, msc)
        self.assertEqual(msc3.machine_snapshot, ms)
        self.assertEqual(msc3.update_diff(),
                         {"last_seen": {"added": last_seen3, "removed": last_seen}})
