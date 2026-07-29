import copy
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from dateutil import parser
from django.core.cache import cache
from django.db import IntegrityError
from django.test import TestCase, override_settings
from django.utils.timezone import is_aware, make_naive

from zentral.contrib.inventory.conf import (
    DESKTOP,
    LAPTOP,
    MACOS,
    MOBILE,
    SERVER,
    VM,
    os_version_display,
    os_version_version_display,
    update_ms_tree_platform,
    update_ms_tree_type,
)
from zentral.contrib.inventory.models import (
    BusinessUnit,
    Certificate,
    CurrentMachineSnapshot,
    MachineSnapshot,
    MachineSnapshotCommit,
    MachineTag,
    MetaMachine,
    Source,
    SourceManager,
    Tag,
)
from zentral.contrib.inventory.utils.db import inventory_events_from_machine_snapshot_commit
from zentral.utils.mt_models import Hasher, MTOError, prepare_commit_tree
from zentral.utils.time import naive_utcnow


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class MachineSnapshotTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.serial_number = "GODZILLAKOMMT"
        cls.os_version = {'name': 'OS X',
                          'major': 10,
                          'minor': 11,
                          'patch': 1}
        cls.os_version_2 = dict(cls.os_version, patch=2, version="(a)")
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
        cls.certificate1 = {'common_name': 'Yolo-ID-1',
                            'organization': 'Zentral',
                            'organizational_unit': 'Zentral IT',
                            'sha_1': '611e5b662c593a08ff58d14ae22452d198df6c6f',
                            'sha_256': 'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f023',
                            'valid_from': parser.parse('2022/01/01 23:40:36 +0200'),
                            'valid_until': parser.parse('2042/01/01 22:40:36 +0100')}
        cls.certificate2 = {'common_name': 'Fomo-ID-1',
                            'organization': 'Zentral',
                            'organizational_unit': 'Zentral IT',
                            'sha_1': '611e5b662c593a08ff58d14ae22452d198df6c6a',
                            'sha_256': 'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f022',
                            'valid_from': parser.parse('2022/01/01 23:40:36 +0200'),
                            'valid_until': parser.parse('2042/01/01 22:40:36 +0100')}
        cls.osx_app_instance = {'app': cls.osx_app,
                                'bundle_path': "/Applications/Baller.app",
                                'executable_path': "/Application/Baller_path",
                                'team_id': "ABCDE12345",
                                'cd_hash': "0123456789abcdef0123456789abcdef01234567",
                                'entitlements': {"com.apple.security.app-sandbox": True,
                                                 "com.apple.security.network.client": True},
                                'signing_time': datetime(2024, 1, 2, 3, 4, 5),
                                'secure_signing_time': datetime(2024, 1, 2, 3, 4, 6),
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
            "source": copy.deepcopy(cls.source)
        }
        cls.extra_facts = {"un": ["1", 2, 3.4],
                           "deux": 2,
                           "trois": {"trois": 3},
                           "4": [1, 3, 2, 5]}
        cls.business_unit, _ = BusinessUnit.objects.commit(cls.business_unit_tree)
        cls.meta_business_unit = cls.business_unit.meta_business_unit
        cls.machine_snapshot = {'source': copy.deepcopy(cls.source),
                                'business_unit': cls.business_unit_tree,
                                'serial_number': cls.serial_number,
                                'osx_app_instances': []}
        cls.machine_snapshot_source_error = {'source': "raise_error",
                                             'serial_number': cls.serial_number,
                                             'os_version': cls.os_version,
                                             'osx_app_instances': [cls.osx_app_instance]}
        cls.machine_snapshot2 = {'source': copy.deepcopy(cls.source),
                                 'business_unit': cls.business_unit_tree,
                                 'serial_number': cls.serial_number,
                                 'os_version': cls.os_version_2,
                                 'osx_app_instances': [cls.osx_app_instance]}
        cls.machine_snapshot3 = {'source': copy.deepcopy(cls.source),
                                 'business_unit': cls.business_unit_tree,
                                 'serial_number': cls.serial_number,
                                 'os_version': cls.os_version_2,
                                 'osx_app_instances': [cls.osx_app_instance, cls.osx_app_instance2]}
        cls.machine_snapshot4 = {'source': copy.deepcopy(cls.source),
                                 'business_unit': cls.business_unit_tree,
                                 'serial_number': cls.serial_number,
                                 'os_version': cls.os_version_2,
                                 'osx_app_instances': [cls.osx_app_instance],
                                 'extra_facts': cls.extra_facts}
        cls.machine_snapshot5 = {'source': copy.deepcopy(cls.source),
                                 'business_unit': cls.business_unit_tree,
                                 'serial_number': cls.serial_number,
                                 'os_version': cls.os_version_2,
                                 'osx_app_instances': [cls.osx_app_instance],
                                 'extra_facts': cls.extra_facts,
                                 'certificates': [cls.certificate1, cls.certificate2]}

    def test_machine_snapshot_commit_create(self):
        tree = copy.deepcopy(self.machine_snapshot)
        msc, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
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
        msc2, ms2, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(ms, ms2)
        self.assertEqual(
            list(inventory_events_from_machine_snapshot_commit(msc2)),
            [('inventory_heartbeat', msc2.last_seen, {'source': self.source})]
        )
        self.assertEqual(CurrentMachineSnapshot.objects.all().count(), 1)
        cms = CurrentMachineSnapshot.objects.get(serial_number=self.serial_number, source=ms.source)
        self.assertEqual(cms.machine_snapshot, ms)
        self.assertEqual(cms.last_seen, msc2.last_seen)

    def test_machine_snapshot_commit_system_uptime(self):
        tree = copy.deepcopy(self.machine_snapshot)
        tree["system_uptime"] = 180
        msc, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(msc.system_uptime, 180)

    def test_machine_snapshot_commit_system_uptime_for_display(self):
        tree = copy.deepcopy(self.machine_snapshot)
        tree["system_uptime"] = 3780
        msc, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(msc.get_system_update_display(), "1\xa0hour, 3\xa0minutes")

    def test_machine_snapshot_commit_missing_system_uptime_for_display(self):
        tree = copy.deepcopy(self.machine_snapshot)
        msc, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertIsNone(msc.get_system_update_display())

    def test_machine_snapshot_commit_different_snapshot_race_skips(self):
        # a concurrent commit took the version with a different snapshot -> skip, don't 500
        msc1, ms1, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(
            copy.deepcopy(self.machine_snapshot))

        def losing_create(**kwargs):
            raise IntegrityError("duplicate key value violates unique constraint")

        with patch.object(MachineSnapshotCommit.objects, "create", side_effect=losing_create), \
             patch.object(MachineSnapshotCommit.objects, "get",
                          return_value=Mock(machine_snapshot=ms1, last_seen=msc1.last_seen)):
            msc2, ms2, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(
                copy.deepcopy(self.machine_snapshot5))
        self.assertIsNone(msc2)
        self.assertNotEqual(ms2, ms1)
        self.assertEqual(
            MachineSnapshotCommit.objects.filter(serial_number=self.serial_number, source=ms1.source).count(),
            1,
        )

    def test_machine_snapshot_commit_same_snapshot_race_skips(self):
        msc1, ms1, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(
            copy.deepcopy(self.machine_snapshot))
        tree = copy.deepcopy(self.machine_snapshot5)
        update_ms_tree_platform(tree)
        update_ms_tree_type(tree)
        ms2 = MachineSnapshot.objects.commit(tree)[0]

        def losing_create(**kwargs):
            raise IntegrityError("duplicate key value violates unique constraint")

        with patch.object(MachineSnapshotCommit.objects, "create", side_effect=losing_create), \
             patch.object(MachineSnapshotCommit.objects, "get",
                          return_value=Mock(machine_snapshot=ms2, last_seen=msc1.last_seen)):
            msc2, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(
                copy.deepcopy(self.machine_snapshot5))
        self.assertIsNone(msc2)
        self.assertEqual(ms, ms2)

    def test_machine_snapshot_commit_source_error(self):
        tree = copy.deepcopy(self.machine_snapshot_source_error)
        with self.assertRaises(MTOError,
                               msg="Field 'source' of MachineSnapshot has "
                                   "many_to_one: True, many_to_many: False"):
            MachineSnapshot.objects.commit(tree)

    def test_machine_snapshot_commit_update(self):
        tree = copy.deepcopy(self.machine_snapshot)
        msc1, ms1, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        ms1.refresh_from_db()
        self.assertEqual(ms1.hash(), ms1.mt_hash)
        self.assertIsInstance(msc1, MachineSnapshotCommit)
        tree = copy.deepcopy(self.machine_snapshot2)
        msc2, ms2, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        ms2.refresh_from_db()
        self.assertEqual(ms2.hash(), ms2.mt_hash)
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
                         {"os_version": {"added": self.os_version_2},
                          "osx_app_instances": {"added": [osx_app_instance_diff]},
                          "last_seen": {"added": msc2.last_seen,
                                        "removed": msc1.last_seen},
                          "platform": {"added": MACOS}})  # don't forget platform !!!
        events = list(inventory_events_from_machine_snapshot_commit(msc2))
        self.assertEqual(
            events,
            [('add_machine_osx_app_instance', None,
              {"osx_app_instance": osx_app_instance_diff, "source": self.source}),
             ('add_machine_os_version', None,
              {'os_version': self.os_version_2, 'source': self.source}),
             ('inventory_heartbeat', msc2.last_seen, {'source': self.source})]
        )
        tree = copy.deepcopy(self.machine_snapshot3)
        msc3, ms3, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        ms3.refresh_from_db()
        self.assertEqual(ms3.hash(), ms3.mt_hash)
        self.assertEqual(msc3.parent, msc2)
        self.assertEqual(CurrentMachineSnapshot.objects.all().count(), 1)
        cms = CurrentMachineSnapshot.objects.get(serial_number=self.serial_number, source=ms3.source)
        self.assertEqual(cms.machine_snapshot, ms3)
        osx_app_instance2_diff = copy.deepcopy(self.osx_app_instance2)
        prepare_diff_dict(osx_app_instance2_diff)
        self.assertEqual(msc3.update_diff(),
                         {"last_seen": {"added": msc3.last_seen, "removed": msc2.last_seen},
                          "osx_app_instances": {"added": [osx_app_instance2_diff]}})
        self.assertEqual(
            list(inventory_events_from_machine_snapshot_commit(msc3)),
            [('add_machine_osx_app_instance', None,
              {'osx_app_instance': osx_app_instance2_diff, "source": self.source}),
             ('inventory_heartbeat', msc3.last_seen, {'source': self.source})]
        )
        self.assertEqual(ms3.mt_hash, ms3.hash())
        self.assertEqual(Certificate.objects.count(), 1)
        tree = copy.deepcopy(self.machine_snapshot2)
        msc4, ms4, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(
            list(inventory_events_from_machine_snapshot_commit(msc4)),
            [('remove_machine_osx_app_instance', None,
              {'osx_app_instance': osx_app_instance2_diff, "source": self.source}),
             ('inventory_heartbeat', msc4.last_seen, {'source': self.source})]
        )
        ms4.refresh_from_db()
        self.assertEqual(ms4.hash(), ms4.mt_hash)
        self.assertEqual(ms4, ms2)
        self.assertEqual(msc4.parent, msc3)
        self.assertEqual(msc4.machine_snapshot, ms2)
        self.assertEqual(CurrentMachineSnapshot.objects.all().count(), 1)
        cms = CurrentMachineSnapshot.objects.get(serial_number=self.serial_number, source=ms4.source)
        self.assertEqual(cms.machine_snapshot, ms2)
        tree = copy.deepcopy(self.machine_snapshot4)
        msc5, ms5, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(
            list(inventory_events_from_machine_snapshot_commit(msc5)),
            [('add_machine_extra_facts', None,
              {'extra_facts': self.extra_facts, "source": self.source}),
             ('inventory_heartbeat', msc5.last_seen, {"source": self.source})]
        )
        self.assertEqual(ms5.extra_facts, self.extra_facts)
        ms5.refresh_from_db()
        self.assertEqual(ms5.hash(), ms5.mt_hash)
        self.assertEqual(msc5.parent, msc4)
        tree = copy.deepcopy(self.machine_snapshot4)
        msc6, ms6, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        ms6.refresh_from_db()
        self.assertEqual(ms6.hash(), ms6.mt_hash)
        self.assertEqual(list(inventory_events_from_machine_snapshot_commit(msc6)),
                         [('inventory_heartbeat', msc6.last_seen, {"source": self.source})])
        self.assertEqual(msc6.parent, msc5)
        self.assertEqual(ms6, ms5)

    def test_duplicated_subtrees(self):
        tree = copy.deepcopy(self.machine_snapshot3)
        tree["osx_app_instances"].append(copy.deepcopy(self.osx_app_instance2))
        with self.assertLogs("zentral.utils.mt_models", level="WARNING") as cm:
            ms, created = MachineSnapshot.objects.commit(tree)
        self.assertEqual(
            cm.output,
            ["WARNING:zentral.utils.mt_models:1 duplicated subtree(s) removed from key osx_app_instances"]
        )
        self.assertTrue(created)
        self.assertEqual(ms.osx_app_instances.count(), 2)
        ms.refresh_from_db()
        self.assertEqual(ms.hash(), ms.mt_hash)
        # same snapshot as the one committed from the tree without the duplicate
        ms2, created2 = MachineSnapshot.objects.commit(copy.deepcopy(self.machine_snapshot3))
        self.assertFalse(created2)
        self.assertEqual(ms, ms2)

    def test_prepare_commit_tree_datetime_list_items(self):
        dt = parser.parse('2035/02/09 22:40:36 +0100')
        tree = {"un": [dt]}
        prepare_commit_tree(tree)
        tree_naive = {"un": [make_naive(dt)]}
        prepare_commit_tree(tree_naive)
        self.assertEqual(tree["mt_hash"], tree_naive["mt_hash"])

    def test_prepare_commit_tree_unsupported_list_item_type(self):
        with self.assertRaises(MTOError) as cm:
            prepare_commit_tree({"un": [object()]})
        self.assertEqual(cm.exception.message, "Unsupported list item type")

    def test_duplicated_subtrees_in_json_field(self):
        tree = copy.deepcopy(self.machine_snapshot)
        tree["extra_facts"] = {"un": [{"a": 1}, {"a": 1}, "deux"]}
        with self.assertLogs("zentral.utils.mt_models", level="WARNING") as cm:
            ms, _ = MachineSnapshot.objects.commit(tree)
        self.assertEqual(
            cm.output,
            ["WARNING:zentral.utils.mt_models:1 duplicated subtree(s) removed from key un"]
        )
        self.assertEqual(ms.extra_facts, {"un": [{"a": 1}, "deux"]})
        ms.refresh_from_db()
        self.assertEqual(ms.hash(), ms.mt_hash)

    def test_commit_certificate(self):
        tree = copy.deepcopy(self.certificate)
        cert, _ = Certificate.objects.commit(tree)
        cert.refresh_from_db()
        self.assertEqual(cert.hash(), cert.mt_hash)
        self.assertEqual(cert.short_repr(), "Apple Root CA")

    def test_certificate_short_repr_missing_cn(self):
        tree = copy.deepcopy(self.certificate)
        tree.pop("common_name")
        cert, _ = Certificate.objects.commit(tree)
        self.assertEqual(cert.short_repr(), "Apple Inc.")

    def test_certificate_short_repr_missing_cn_o(self):
        tree = copy.deepcopy(self.certificate)
        tree.pop("common_name")
        tree.pop("organization")
        cert, _ = Certificate.objects.commit(tree)
        self.assertEqual(cert.short_repr(), "Apple Certification Authority")

    def test_commit_certificate_serialized_datetimes(self):
        tree = copy.deepcopy(self.certificate)
        tree["valid_from"] = "2006-04-25T21:40:36Z"
        tree["valid_until"] = "2035-02-09T21:40:36Z"
        cert, created = Certificate.objects.commit(tree)
        self.assertTrue(created)
        cert.refresh_from_db()
        self.assertEqual(cert.hash(), cert.mt_hash)
        self.assertEqual(cert.valid_from, datetime(2006, 4, 25, 21, 40, 36))
        self.assertEqual(cert.valid_until, datetime(2035, 2, 9, 21, 40, 36))
        # same certificate serialized with datetime objects → same object
        cert2, created2 = Certificate.objects.commit(copy.deepcopy(self.certificate))
        self.assertFalse(created2)
        self.assertEqual(cert, cert2)

    def test_commit_certificate_equivalent_serialized_datetimes(self):
        mt_hashes = set()
        pks = set()
        for valid_from in ("2022-01-01T21:40:36Z",
                           "2022-01-01T21:40:36+00:00",
                           "2022-01-01T23:40:36+02:00",
                           "2022-01-01 21:40:36",
                           datetime(2022, 1, 1, 21, 40, 36)):
            tree = copy.deepcopy(self.certificate1)
            tree["valid_from"] = valid_from
            cert, _ = Certificate.objects.commit(tree)
            mt_hashes.add(cert.mt_hash)
            pks.add(cert.pk)
        self.assertEqual(len(mt_hashes), 1)
        self.assertEqual(len(pks), 1)

    def test_commit_certificate_invalid_serialized_datetime(self):
        tree = copy.deepcopy(self.certificate)
        tree["valid_from"] = "yolo"
        with self.assertRaises(MTOError) as cm:
            Certificate.objects.commit(tree)
        self.assertEqual(cm.exception.message, 'Invalid serialized datetime "yolo" for field valid_from')

    def test_commit_machine_snapshot_tree_serialized_datetimes(self):
        tree = copy.deepcopy(self.machine_snapshot3)
        for osx_app_instance in tree["osx_app_instances"]:
            signed_by = osx_app_instance["signed_by"]
            signed_by["valid_from"] = "2006-04-25T21:40:36Z"
            signed_by["valid_until"] = "2035-02-09T21:40:36Z"
        tree["certificates"] = [{"common_name": "Zentral CA",
                                 "organization": "Zentral",
                                 "valid_from": "2015-10-16T04:17:39Z",
                                 "valid_until": "2025-10-13T04:17:39Z"}]
        tree["profiles"] = [{"uuid": "e6dd0e0b-0f92-4a58-9d41-3a4c04a1b7dd",
                             "display_name": "Zentral Profile",
                             "install_date": "2026-04-01T08:30:31Z"}]
        tree["program_instances"] = [{"program": {"name": "Zentral Agent", "version": "1.0"},
                                      "install_date": "2026-04-01T10:30:31+02:00"}]
        msc, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        ms.refresh_from_db()
        self.assertEqual(ms.hash(), ms.mt_hash)
        certificate = ms.certificates.get()
        self.assertEqual(certificate.valid_from, datetime(2015, 10, 16, 4, 17, 39))
        profile = ms.profiles.get()
        self.assertEqual(profile.install_date, datetime(2026, 4, 1, 8, 30, 31))
        program_instance = ms.program_instances.get()
        self.assertEqual(program_instance.install_date, datetime(2026, 4, 1, 8, 30, 31))

    def test_commit_extra_facts_serialized_datetime_untouched(self):
        tree = copy.deepcopy(self.machine_snapshot)
        tree["extra_facts"] = {"last_boot": "2026-04-01T08:30:31Z"}
        ms, _ = MachineSnapshot.objects.commit(tree)
        ms.refresh_from_db()
        self.assertEqual(ms.extra_facts, {"last_boot": "2026-04-01T08:30:31Z"})
        self.assertEqual(ms.hash(), ms.mt_hash)

    def test_prepare_commit_tree_no_model_serialized_datetime_untouched(self):
        tree = {"un": "2026-04-01T08:30:31Z"}
        prepare_commit_tree(tree)
        self.assertEqual(tree["un"], "2026-04-01T08:30:31Z")

    def test_ordered_certificates(self):
        tree = copy.deepcopy(self.machine_snapshot5)
        _, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        cert1, cert2 = [cert for cert in ms.ordered_certificates()]
        self.assertEqual(cert1.common_name, "Fomo-ID-1")
        self.assertEqual(cert2.common_name, "Yolo-ID-1")

    def test_source(self):
        tree = copy.deepcopy(self.machine_snapshot3)
        msc, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        tree = copy.deepcopy(self.machine_snapshot3)
        tree["serial_number"] = tree["serial_number"][::-1]
        msc2, ms2, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
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
        msc, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(MachineSnapshot.objects.current_platforms(),
                         [(MACOS, "macOS")])

    def test_machine_snapshot_current_type(self):
        tree = copy.deepcopy(self.machine_snapshot3)
        tree["system_info"] = {"hardware_model": "imac"}
        msc, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(MachineSnapshot.objects.current_types(),
                         [(DESKTOP, "Desktop")])

    def test_machine_snapshot_current(self):
        tree = copy.deepcopy(self.machine_snapshot)
        msc, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        tree = copy.deepcopy(self.machine_snapshot2)
        msc2, ms2, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        tree = copy.deepcopy(self.machine_snapshot3)
        msc3, ms3, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(MachineSnapshot.objects.count(), 3)
        self.assertEqual(MachineSnapshot.objects.current().count(), 1)
        self.assertEqual(MachineSnapshot.objects.current().get(pk=ms3.id), ms3)
        mm = MetaMachine(self.serial_number)
        mm.archive()
        self.assertEqual(CurrentMachineSnapshot.objects.count(), 0)
        tree = copy.deepcopy(self.machine_snapshot3)
        msc4, ms4, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(ms3, ms4)
        self.assertEqual(CurrentMachineSnapshot.objects.count(), 1)
        cms = CurrentMachineSnapshot.objects.get(serial_number=self.serial_number)
        self.assertEqual(cms.machine_snapshot, ms3)

    def test_has_recent_source_snapshot(self):
        tree = copy.deepcopy(self.machine_snapshot)
        module = self.source["module"]
        age = 7200
        last_seen = naive_utcnow() - timedelta(seconds=age)
        tree["last_seen"] = last_seen
        msc, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
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
        msc, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        tree = copy.deepcopy(self.machine_snapshot2)
        msc2, ms2, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        tree = copy.deepcopy(self.machine_snapshot3)
        msc3, ms3, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        mm = MetaMachine(self.serial_number)
        self.assertEqual(mm.serial_number, self.serial_number)
        self.assertEqual(mm.snapshots, [ms3])
        self.assertEqual(mm.platform, MACOS)
        tag1, _ = Tag.objects.get_or_create(name="tag111")
        tag2, _ = Tag.objects.get_or_create(name="tag222")
        MachineTag.objects.create(tag=tag1, serial_number=self.serial_number)
        self.assertEqual((MACOS, None, {self.meta_business_unit.id}, {tag1.id}),
                         mm.get_probe_filtering_values())
        # cached
        self.assertEqual((MACOS, None, {self.meta_business_unit.id}, {tag1.id}),
                         mm.get_probe_filtering_values())
        # fresh
        mm = MetaMachine(self.serial_number)
        self.assertEqual((MACOS, None, {self.meta_business_unit.id}, {tag1.id}),
                         mm.get_probe_filtering_values())
        # cached with cache framework
        mm = MetaMachine(self.serial_number)
        self.assertEqual((MACOS, None, {self.meta_business_unit.id}, {tag1.id}),
                         mm.cached_probe_filtering_values)
        self.assertEqual((MACOS, None, {self.meta_business_unit.id}, {tag1.id}),
                         cache.get("mm-probe-fvs_{}".format(mm.get_urlsafe_serial_number())))

        # get_serialized_info_for_event
        mm = MetaMachine(self.serial_number)
        sife = mm.get_serialized_info_for_event()
        self.assertEqual(
            sife["meta_business_units"],
            [{"id": self.meta_business_unit.pk,
              "name": self.meta_business_unit.name}]
        )
        self.assertEqual(sife["platform"], "MACOS")
        self.assertEqual(
            sife["zentral"],
            {'business_unit': {'key': self.business_unit.get_short_key(),
                               'name': self.business_unit.name,
                               'reference': self.business_unit.reference},
             'os_version': 'OS X 10.11.2 (a)'}
        )

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
        msc, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(copy.deepcopy(tree))
        self.assertEqual(ms.get_machine_str(), "yo")
        tree["system_info"] = {"hostname": "hostname yo"}
        msc, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(copy.deepcopy(tree))
        self.assertEqual(ms.get_machine_str(), "hostname yo")
        tree["system_info"] = {"computer_name": "computername yo",
                               "hostname": "hostname yo"}
        msc, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(copy.deepcopy(tree))
        self.assertEqual(ms.get_machine_str(), "computername yo")

    # update ms tree

    def test_update_ms_tree_type_hardware_model(self):
        for hardware_model, machine_type in (("IMac", DESKTOP),
                                             ("Mac14,10", LAPTOP),
                                             ("Mac14,12", DESKTOP),
                                             ("MacBookPro18,3", LAPTOP),
                                             ("Virtual Machine", VM)):
            tree = {"system_info": {"hardware_model": hardware_model}}
            update_ms_tree_type(tree)
            self.assertEqual(tree.get("type"), machine_type)
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

    def test_update_ms_tree_type_model_unknown_cpu_brand_known(self):
        tree = {"system_info": {"hardware_model": "kjwelkjdwlkej",
                                "cpu_brand": "Xeon godz"}}
        update_ms_tree_type(tree)
        self.assertEqual(tree.get("type"), SERVER)

    def test_update_ms_tree_type_model_unknown_cpu_brand_unknown(self):
        tree = {"system_info": {"hardware_model": "kjwelkjdwlkej",
                                "cpu_brand": "Godz"}}
        update_ms_tree_type(tree)
        self.assertEqual(tree.get("type"), None)

    def test_update_ms_tree_type_model_known_cpu_brand_known(self):
        tree = {"system_info": {"hardware_model": "Precision 3630 Tower",
                                "cpu_brand": "Xeon"}}
        update_ms_tree_type(tree)
        self.assertEqual(tree.get("type"), DESKTOP)

    def test_update_ms_tree_type_model_known_2_cpu_brand_unknown(self):
        tree = {"system_info": {"hardware_model": "HP EliteBook 840 G5",
                                "cpu_brand": "Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz"}}
        update_ms_tree_type(tree)
        self.assertEqual(tree.get("type"), LAPTOP)

    def test_update_ms_tree_type_model_known_3_cpu_brand_unknown(self):
        tree = {"system_info": {"hardware_model": "google Pixel",
                                "cpu_brand": "IQJNQE"}}
        update_ms_tree_type(tree)
        self.assertEqual(tree.get("type"), MOBILE)

    # os version number display

    def test_os_version_version_display(self):
        os_version = {"major": 10, "minor": 15, "patch": None}
        self.assertEqual(os_version_version_display(os_version), "10.15")

    def test_os_version_version_display_drop_number(self):
        os_version = {"name": "Windows 10", "major": 10, "version": "21H2", "build": "19044.1682"}
        self.assertEqual(os_version_version_display(os_version), "21H2")

    def test_os_version_display(self):
        os_version = {"name": "macOS", "major": 12, "minor": 3, "patch": 1, "build": "21E258"}
        self.assertEqual(os_version_display(os_version), "macOS 12.3.1 (21E258)")

    def test_os_version_display_drop_number(self):
        os_version = {"name": "Windows 10", "major": 10, "version": "21H2", "build": "19044.1682"}
        self.assertEqual(os_version_display(os_version), "Windows 10 21H2 (19044.1682)")

    # last seen

    def test_last_seen(self):
        tree = copy.deepcopy(self.machine_snapshot)
        last_seen = naive_utcnow()
        tree["last_seen"] = last_seen
        msc, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(msc.last_seen, last_seen)
        tree = copy.deepcopy(self.machine_snapshot)
        tree["last_seen"] = last_seen
        msc2, ms2, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(msc2, None)
        tree = copy.deepcopy(self.machine_snapshot)
        last_seen3 = naive_utcnow()
        tree["last_seen"] = last_seen3
        msc3, ms3, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(msc3.last_seen, last_seen3)
        self.assertEqual(msc3.parent, msc)
        self.assertEqual(msc3.machine_snapshot, ms)
        self.assertEqual(msc3.update_diff(),
                         {"last_seen": {"added": last_seen3, "removed": last_seen}})

    def test_last_seen_naive_string(self):
        tree = copy.deepcopy(self.machine_snapshot)
        tree["last_seen"] = "2026-07-24T10:11:12"
        msc, _, last_seen = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(msc.last_seen, datetime(2026, 7, 24, 10, 11, 12))
        self.assertEqual(last_seen, datetime(2026, 7, 24, 10, 11, 12))

    def test_last_seen_aware_string(self):
        tree = copy.deepcopy(self.machine_snapshot)
        tree["last_seen"] = "2026-07-24T10:11:12+02:00"
        msc, _, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(msc.last_seen, datetime(2026, 7, 24, 8, 11, 12))
        tree = copy.deepcopy(self.machine_snapshot)
        tree["last_seen"] = "2026-07-24T10:11:12Z"
        msc2, _, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(msc2.last_seen, datetime(2026, 7, 24, 10, 11, 12))

    def test_last_seen_unparseable_string(self):
        tree = copy.deepcopy(self.machine_snapshot)
        tree["last_seen"] = "yolo"
        t0 = naive_utcnow()
        with self.assertLogs("zentral.contrib.inventory.models", level="ERROR") as cm:
            msc, _, last_seen = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(cm.output,
                         ["ERROR:zentral.contrib.inventory.models:Could not parse commit tree last_seen"])
        self.assertTrue(t0 <= msc.last_seen <= naive_utcnow())
        self.assertEqual(msc.last_seen, last_seen)

    def test_last_seen_aware_datetime(self):
        tree = copy.deepcopy(self.machine_snapshot)
        tree["last_seen"] = parser.parse("2026-07-24T10:11:12+02:00")
        msc, _, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(msc.last_seen, datetime(2026, 7, 24, 8, 11, 12))

    def test_last_seen_missing(self):
        tree = copy.deepcopy(self.machine_snapshot)
        t0 = naive_utcnow()
        with self.assertNoLogs("zentral.contrib.inventory.models", level="ERROR"):
            msc, _, last_seen = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertTrue(t0 <= msc.last_seen <= naive_utcnow())
        self.assertEqual(msc.last_seen, last_seen)

    def test_last_seen_wrong_type(self):
        tree = copy.deepcopy(self.machine_snapshot)
        tree["last_seen"] = 17
        t0 = naive_utcnow()
        with self.assertLogs("zentral.contrib.inventory.models", level="ERROR") as cm:
            msc, _, last_seen = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        self.assertEqual(cm.output,
                         ["ERROR:zentral.contrib.inventory.models:Commit tree last seen is not a str or a datetime"])
        self.assertTrue(t0 <= msc.last_seen <= naive_utcnow())
        self.assertEqual(msc.last_seen, last_seen)

    # hasher

    def test_hasher_invalid_field_name(self):
        with self.assertRaises(ValueError) as cm:
            Hasher().add_field(None, "yolo")
        self.assertEqual(cm.exception.args[0], "Invalid field name None")

    def test_hasher_field_already_added(self):
        hasher = Hasher()
        hasher.add_field("un", "yolo")
        with self.assertRaises(ValueError) as cm:
            hasher.add_field("un", "fomo")
        self.assertEqual(cm.exception.args[0], "Field un already added")

    def test_hasher_invalid_field_value(self):
        with self.assertRaises(ValueError) as cm:
            Hasher().add_field("un", 1.2)
        self.assertEqual(cm.exception.args[0], "Invalid field value 1.2 for field un")

    def test_hasher_aware_datetime(self):
        hasher = Hasher()
        hasher.add_field("un", parser.parse("2026-07-24T10:11:12+02:00"))
        naive_hasher = Hasher()
        naive_hasher.add_field("un", datetime(2026, 7, 24, 8, 11, 12))
        self.assertEqual(hasher.hexdigest(), naive_hasher.hexdigest())

    # commit tree

    def test_prepare_commit_tree_not_a_dict(self):
        with self.assertRaises(MTOError) as cm:
            prepare_commit_tree(["yolo"])
        self.assertEqual(cm.exception.message, "Commit tree is not a dict")

    def test_commit_dict_value_for_text_field(self):
        with self.assertRaises(MTOError) as cm:
            Source.objects.commit({"module": {"un": 1}, "name": "yolo"})
        self.assertEqual(cm.exception.message, 'Cannot set field "module" to dict value')

    def test_commit_concurrently_created_object(self):
        source, _ = Source.objects.commit(copy.deepcopy(self.source))
        tree = dict(self.source, name="fomo")
        with patch.object(SourceManager, "get", side_effect=[Source.DoesNotExist, source]), \
             patch.object(Source, "save", side_effect=IntegrityError):
            obj, created = Source.objects.commit(tree)
        self.assertFalse(created)
        self.assertEqual(obj, source)

    def test_commit_integrity_error_not_a_key_error(self):
        tree = dict(self.source, name="fomo")
        with patch.object(SourceManager, "get", side_effect=Source.DoesNotExist), \
             patch.object(Source, "save", side_effect=IntegrityError):
            with self.assertRaises(IntegrityError):
                Source.objects.commit(tree)

    def test_commit_hash_mismatch(self):
        tree = dict(self.source, name="fomo")
        with patch.object(Source, "hash", return_value="yolo"):
            with self.assertRaises(MTOError) as cm:
                Source.objects.commit(tree)
        self.assertEqual(cm.exception.message, "Obj fomo Hash missmatch!!!")
        # the row is rolled back with the mismatch, it is not left under the wrong identity
        self.assertEqual(Source.objects.filter(name="fomo").count(), 0)

    def test_commit_hash_mismatch_per_object_path(self):
        # BusinessUnit overrides save(), so it is never bulk inserted
        tree = {"name": "fomo", "reference": "fomo 1", "source": copy.deepcopy(self.source)}
        with patch.object(BusinessUnit, "hash", return_value="yolo"):
            with self.assertRaises(MTOError) as cm:
                BusinessUnit.objects.commit(tree)
        self.assertEqual(cm.exception.message, "Obj fomo Hash missmatch!!!")
        self.assertEqual(BusinessUnit.objects.filter(name="fomo").count(), 0)

    # mt fields

    def test_get_mt_field_excluded(self):
        with self.assertRaises(MTOError) as cm:
            Source().get_mt_field("mt_hash")
        self.assertEqual(cm.exception.message, "Field 'mt_hash' of Source is excluded")

    def test_get_mt_field_auto_created(self):
        with self.assertRaises(MTOError) as cm:
            Source().get_mt_field("machinesnapshot")
        self.assertEqual(cm.exception.message, "Field 'machinesnapshot' of Source auto created")

    def test_serialize_unsupported_value_type(self):
        source, _ = Source.objects.commit(copy.deepcopy(self.source))
        source.config = [1, 2]
        with self.assertRaises(ValueError) as cm:
            source.serialize()
        self.assertEqual(cm.exception.args[0], "Can't serialize Source.config value of type <class 'list'>")

    def test_diff_different_model(self):
        source, _ = Source.objects.commit(copy.deepcopy(self.source))
        certificate, _ = Certificate.objects.commit(copy.deepcopy(self.certificate))
        with self.assertRaises(MTOError) as cm:
            source.diff(certificate)
        self.assertEqual(cm.exception.message, "Can only compare to an object of the same model")

    def test_diff_removed_mt_object(self):
        ms, _ = MachineSnapshot.objects.commit(copy.deepcopy(self.machine_snapshot2))
        ms2, _ = MachineSnapshot.objects.commit(copy.deepcopy(self.machine_snapshot))
        self.assertEqual(ms2.diff(ms)["os_version"], {"removed": ms.os_version.serialize()})
