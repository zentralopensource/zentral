import hashlib
import re
from django.test import TestCase
from zentral.core.events import event_types
from zentral.core.events.base import EventMetadata
from zentral.core.probes.conf import all_probes
from zentral.core.probes.models import ProbeSource
from zentral.contrib.osquery.conf import INVENTORY_QUERY_NAME, build_osquery_conf
from zentral.contrib.osquery.probes import OsqueryComplianceProbe
from tests.inventory.utils import MockMetaMachine


payload_template = {
    "action": "added",
    "hostIdentifier": "yo",
    "calendarTime": "Tue Nov 22 21:41:01 2016 UTC",
    "columns": {
        # TODO
    },
    "unixTime": "1479850861"
}


def build_osquery_result_event(query_name):
    OsqueryResult = event_types["osquery_result"]
    payload = payload_template.copy()
    payload["name"] = query_name
    return OsqueryResult(EventMetadata(machine_serial_number="YO",
                                       event_type=OsqueryResult.event_type),
                         payload)


class OsqueryComplianceProbeTestCase(TestCase):
    @staticmethod
    def sha1_8(s):
        return hashlib.sha1(s.encode("utf-8")).hexdigest()[:8]

    @classmethod
    def setUpTestData(cls):
        # probe user preference file
        cls.query_pfu_query = (
            "select username, filename, key, value from "
            "(select * from users where directory like '/Users/%') u, "
            "plist p, file f "
            "WHERE ("
            "(p.path like u.directory || '/Library/Preferences/%onepassword4%') or "
            "(p.path like u.directory || '/Library/Preferences/%/%onepassword4%')"
            ") and ("
            "(key = 'LockTimeout' and ((CAST(value as integer) < 1) or (CAST(value as integer) > 10))) or "
            "(key = 'LockOnScreenSaver' and ((value <> 'true')))) "
            "and f.path = p.path"
        )
        cls.query_pfu_key = "osquery-compliance-probe-pfu_pf_{}".format(cls.sha1_8(cls.query_pfu_query))
        cls.probe_source_pfu = ProbeSource.objects.create(
            model="OsqueryComplianceProbe",
            name="osquery compliance probe pfu",
            status=ProbeSource.ACTIVE,
            body={"preference_files": [{"type": "USERS",
                                        "rel_path": "%onepassword4%",
                                        "keys": [{"key": "LockTimeout", "min_value": 1, "max_value": 10},
                                                 {"key": "LockOnScreenSaver", "value": "true"}],
                                        }]}
        )
        cls.probe_pfu = cls.probe_source_pfu.load()
        # probe global preference file
        cls.query_pfg_query = (
            "select filename, key, value from "
            "plist p, file f "
            "WHERE ("
            "(p.path = '/Library/Preferences/Bluetooth')"
            ") and ("
            "(key = 'ControllerPowerState' and ((value <> '0')))"
            ") and f.path = p.path"
        )
        cls.query_pfg_key = "osquery-compliance-probe-pfg_pf_{}".format(cls.sha1_8(cls.query_pfg_query))
        cls.probe_source_pfg = ProbeSource.objects.create(
            model="OsqueryComplianceProbe",
            name="osquery compliance probe pfg",
            status=ProbeSource.ACTIVE,
            body={"preference_files": [{"type": "GLOBAL",
                                        "rel_path": "Bluetooth",
                                        "keys": [{"key": "ControllerPowerState", "value": "0"}],
                                        "interval": 45
                                        }]}
        )
        cls.probe_pfg = cls.probe_source_pfg.load()
        # probe file checksum
        cls.query_fc_query = (
            "select path, sha256 from hash where (("
            "path = '/home/yo/.bashrc' and "
            "sha256 <> '0123456789012345678901234567890123456789012345678901234567890123'"
            "))"
        )
        cls.query_fc_key = "osquery-compliance-probe-fc_fc_{}".format(cls.sha1_8(cls.query_fc_query))
        cls.probe_source_fc = ProbeSource.objects.create(
            model="OsqueryComplianceProbe",
            name="osquery compliance probe fc",
            status=ProbeSource.ACTIVE,
            body={"file_checksums": [{"path": "/home/yo/.bashrc",
                                      "sha256": "01234567890123456789012345678901"
                                                "23456789012345678901234567890123",
                                      "interval": 100}]}
        )
        cls.probe_fc = cls.probe_source_fc.load()
        # probe tag / file checksum
        cls.query_tag_query = (
            "select path, sha256 from hash where (("
            "path = '/home/tag/.bashrc' and "
            "sha256 <> '0123456789012345678901234567890123456789012345678901234567890123'"
            "))"
        )
        cls.query_tag_key = "osquery-compliance-probe-tag_fc_{}".format(cls.sha1_8(cls.query_tag_query))
        cls.probe_source_tag = ProbeSource.objects.create(
            model="OsqueryComplianceProbe",
            name="osquery compliance probe tag",
            status=ProbeSource.ACTIVE,
            body={"filters": {"inventory": [{"tag_ids": [1]}]},
                  "file_checksums": [{"path": "/home/tag/.bashrc",
                                      "sha256": "01234567890123456789012345678901"
                                                "23456789012345678901234567890123",
                                      }]}
        )
        cls.probe_tag = cls.probe_source_tag.load()
        # clear
        all_probes.clear()

    def test_probes(self):
        for probe in (self.probe_pfu,
                      self.probe_pfg,
                      self.probe_fc,
                      self.probe_tag):
            self.assertTrue(isinstance(probe, OsqueryComplianceProbe))

    def test_fc_root_dir(self):
        self.assertEqual(self.probe_pfu.preference_files[0].get_root_dir(),
                         "/Users/%/Library/Preferences")
        self.assertEqual(self.probe_pfg.preference_files[0].get_root_dir(),
                         "/Library/Preferences")

    def test_fc_paths(self):
        self.assertEqual(self.probe_pfu.preference_files[0].get_paths(),
                         ["/Users/%/Library/Preferences/%/%onepassword4%",
                          "/Users/%/Library/Preferences/%onepassword4%"])
        self.assertEqual(self.probe_pfg.preference_files[0].get_paths(),
                         ["/Library/Preferences/Bluetooth"])

    def test_can_delete_items(self):
        for probe in (self.probe_pfu,
                      self.probe_pfg,
                      self.probe_fc,
                      self.probe_tag):
            self.assertEqual(probe.can_delete_items, False)
            # TODO True

    def test_probes_metadata_filters(self):
        for probe in (self.probe_pfu,
                      self.probe_pfg,
                      self.probe_fc,
                      self.probe_tag):
            self.assertEqual(len(probe.metadata_filters), 1)
            metadata_filter = probe.metadata_filters[0]
            self.assertEqual(metadata_filter.event_types, set(["osquery_result"]))
            self.assertEqual(metadata_filter.event_tags, set([]))

    def test_all_probes(self):
        probes = list(all_probes.class_filter(OsqueryComplianceProbe))
        self.assertEqual(len(probes), 4)

    def test_probe_sources_event_type(self):
        for probe_source in (self.probe_source_pfu,
                             self.probe_source_pfg,
                             self.probe_source_fc,
                             self.probe_source_tag):
            self.assertEqual(probe_source.event_types, ["osquery_result"])

    def test_probes_test_event(self):
        default_machine = MockMetaMachine([], [], None, None)
        tag_machine = MockMetaMachine([1], [1], "WINDOWS", None)
        tests = (
          # wrong hash
          (self.probe_pfu, self.query_pfg_key, default_machine, False),
          (self.probe_pfg, self.query_pfu_key, default_machine, False),
          (self.probe_fc, self.query_pfu_key, tag_machine, False),
          (self.probe_tag, self.query_pfu_key, tag_machine, False),
          # ok
          (self.probe_pfu, self.query_pfu_key, default_machine, True),
          (self.probe_pfg, self.query_pfg_key, default_machine, True),
          (self.probe_tag, self.query_tag_key, tag_machine, True),
          # tag
          (self.probe_tag, self.query_tag_key, default_machine, False),
          (self.probe_tag, self.query_tag_key, tag_machine, True),
        )
        for probe, query_name, machine, result in tests:
            event = build_osquery_result_event(query_name)
            event.metadata.machine = machine  # hack
            self.assertEqual(probe.test_event(event), result)

    def test_scheduled_queries(self):
        for probe, key in ((self.probe_pfu, self.query_pfu_key),
                           (self.probe_pfg, self.query_pfg_key),
                           (self.probe_fc, self.query_fc_key),
                           (self.probe_tag, self.query_tag_key)):
            self.assertTrue(isinstance(probe.scheduled_queries, dict))
            self.assertTrue(key in probe.scheduled_queries)
            for osquery_query in probe.iter_scheduled_queries():
                self.assertIn(osquery_query.result_name, probe.scheduled_queries)

    def test_extra_event_search_dict(self):
        for probe, result_name in ((self.probe_pfu, self.query_pfu_key),
                                   (self.probe_pfg, self.query_pfg_key),
                                   (self.probe_fc, self.query_fc_key),
                                   (self.probe_tag, self.query_tag_key)):
            sd = probe.get_extra_event_search_dict()
            self.assertEqual(sd["event_type"], "osquery_result")
            self.assertEqual([q.result_name for q in probe.iter_scheduled_queries()],
                             [result_name])
            self.assertTrue(re.match(sd["name__regexp"], result_name) is not None)

    def test_osquery_conf(self):
        # default machine has a subset of the queries
        default_machine = MockMetaMachine([], [], None, None)
        config = build_osquery_conf(default_machine, enrollment=None)
        self.assertCountEqual(["decorators", "schedule"], config.keys())  # no file_paths, file_accesses or packs
        schedule = config["schedule"]
        self.assertCountEqual([INVENTORY_QUERY_NAME,
                               self.query_pfu_key, self.query_pfg_key,
                               self.query_fc_key],
                              schedule.keys())

        # tag has all the queries
        tag_machine = MockMetaMachine([], [1], None, "SERVER")
        config = build_osquery_conf(tag_machine, enrollment=None)
        self.assertCountEqual(["decorators", "schedule"], config.keys())  # no file_paths, file_accesses or packs
        schedule = config["schedule"]
        self.assertCountEqual([INVENTORY_QUERY_NAME,
                               self.query_pfu_key, self.query_pfg_key,
                               self.query_fc_key, self.query_tag_key],
                              schedule.keys())
