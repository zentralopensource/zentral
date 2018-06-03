import re
from django.test import TestCase
from zentral.core.events import event_types
from zentral.core.events.base import EventMetadata
from zentral.core.probes.conf import all_probes
from zentral.core.probes.models import ProbeSource
from zentral.contrib.osquery.conf import INVENTORY_QUERY_NAME, build_osquery_conf
from zentral.contrib.osquery.probes import OsqueryFIMProbe
from tests.inventory.utils import MockMetaMachine


payload_template = {
    "action": "added",
    "hostIdentifier": "yo",
    "calendarTime": "Tue Nov 22 21:41:01 2016 UTC",
    "columns": {
        "category": "edef96bc",
        "gid": "20",
        "size": "13365",
        "time": "1479850858",
        "action": "MOVED_TO",
        "sha1": "",
        "mtime": "1479850858",
        "sha256": "",
        "atime": "1479850858",
        "hashed": "0",
        "transaction_id": "9051269",
        "md5": "",
        "target_path": "/Users/yo/.ssh/known_hosts",
        "mode": "0644",
        "ctime": "1479850858",
        "uid": "501",
        "inode": "5709021"
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


class OsqueryFIMProbeTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # probe 1
        cls.query_1_filepath = "/Users/%/.ssh/%%"
        cls.query_1_filepath_hash = "edef96bc"
        cls.query_1_key = "osquery-fim-probe-1_c71292f6"
        cls.probe_source_1 = ProbeSource.objects.create(
            model="OsqueryFIMProbe",
            name="osquery fim probe 1",
            status=ProbeSource.ACTIVE,
            body={"file_paths": [{"file_path": cls.query_1_filepath}]}
        )
        cls.probe_1 = cls.probe_source_1.load()
        # probe 2
        cls.query_2_filepath = "/home/%/.ssh/%%"
        cls.query_2_filepath_hash = "6ca0f872"
        cls.query_2_key = "osquery-fim-probe-2_1c6e39ad"
        cls.probe_source_2 = ProbeSource.objects.create(
            model="OsqueryFIMProbe",
            name="osquery fim probe 2",
            status=ProbeSource.ACTIVE,
            body={"file_paths": [{"file_path": cls.query_2_filepath,
                                  "file_access": True}]}
        )
        cls.probe_2 = cls.probe_source_2.load()
        # probe mbu
        cls.query_mbu_filepath = "/root/.ssh/%%"
        cls.query_mbu_filepath_hash = "35c934e0"
        cls.query_mbu_key = "osquery-fim-probe-mbu_cc871b0b"
        cls.probe_source_mbu = ProbeSource.objects.create(
            model="OsqueryFIMProbe",
            name="osquery fim probe mbu",
            status=ProbeSource.ACTIVE,
            body={"filters": {"inventory": [{"meta_business_unit_ids": [1]}]},
                  "file_paths": [{"file_path": cls.query_mbu_filepath,
                                  "file_access": False}]}
        )
        cls.probe_mbu = cls.probe_source_mbu.load()
        # clear
        all_probes.clear()

    def test_probes(self):
        for probe in (self.probe_1,
                      self.probe_2,
                      self.probe_mbu):
            self.assertTrue(isinstance(probe, OsqueryFIMProbe))

    def test_probes_metadata_filters(self):
        for probe in (self.probe_1,
                      self.probe_2,
                      self.probe_mbu):
            self.assertEqual(len(probe.metadata_filters), 1)
            metadata_filter = probe.metadata_filters[0]
            self.assertEqual(metadata_filter.event_types, set(["osquery_result"]))
            self.assertEqual(metadata_filter.event_tags, set([]))

    def test_all_probes(self):
        probes = list(all_probes.class_filter(OsqueryFIMProbe))
        self.assertEqual(len(probes), 3)

    def test_probe_sources_event_type(self):
        for probe_source in (self.probe_source_1,
                             self.probe_source_2,
                             self.probe_source_mbu):
            self.assertEqual(probe_source.event_types, ["osquery_result"])

    def test_probes_test_event(self):
        default_machine = MockMetaMachine([], [], None, None)
        mbu = MockMetaMachine([1], [1], "WINDOWS", None)
        tests = (
          # wrong hash
          (self.probe_1, self.query_2_key, default_machine, False),
          (self.probe_2, self.query_1_key, mbu, False),
          (self.probe_mbu, self.query_1_key, mbu, False),
          # ok
          (self.probe_1, self.query_1_key, default_machine, True),
          (self.probe_2, self.query_2_key, mbu, True),
          # mbu
          (self.probe_mbu, self.query_mbu_key, default_machine, False),
          (self.probe_mbu, self.query_mbu_key, mbu, True),
        )
        for probe, query_name, machine, result in tests:
            event = build_osquery_result_event(query_name)
            event.metadata.machine = machine  # hack
            self.assertEqual(probe.test_event(event), result)

    def test_scheduled_queries(self):
        for probe, key in ((self.probe_1, self.query_1_key),
                           (self.probe_2, self.query_2_key),
                           (self.probe_mbu, self.query_mbu_key)):
            self.assertTrue(isinstance(probe.scheduled_queries, dict))
            self.assertTrue(key in probe.scheduled_queries)
            for osquery_query in probe.iter_scheduled_queries():
                self.assertIn(osquery_query.result_name, probe.scheduled_queries)

    def test_extra_event_search_dict(self):
        for probe, result_name in ((self.probe_1, self.query_1_key),
                                   (self.probe_2, self.query_2_key),
                                   (self.probe_mbu, self.query_mbu_key)):
            sd = probe.get_extra_event_search_dict()
            self.assertEqual(sd["event_type"], "osquery_result")
            self.assertEqual([q.result_name for q in probe.iter_scheduled_queries()],
                             [result_name])
            self.assertTrue(re.match(sd["name__regexp"], result_name) is not None)

    def test_osquery_conf(self):
        # default machine has a subset of the queries
        default_machine = MockMetaMachine([], [], None, None)
        config = build_osquery_conf(default_machine, enrollment=None)
        self.assertCountEqual(["decorators", "schedule", "file_accesses", "file_paths"],
                              config.keys())  # no packs
        schedule = config["schedule"]
        self.assertCountEqual([INVENTORY_QUERY_NAME,
                               self.query_1_key,
                               self.query_2_key],
                              schedule.keys())
        file_paths = config["file_paths"]
        self.assertCountEqual(file_paths.keys(),
                              [self.query_1_filepath_hash,
                               self.query_2_filepath_hash])
        for key, file_path in ((self.query_1_filepath_hash, self.query_1_filepath),
                               (self.query_2_filepath_hash, self.query_2_filepath)):
            self.assertEqual(file_paths.get(key), [file_path])
        file_accesses = config["file_accesses"]
        self.assertEqual([self.query_2_filepath_hash], file_accesses)

        # mbu has all the queries
        mbu_machine = MockMetaMachine([1], [], None, "SERVER")
        config = build_osquery_conf(mbu_machine, enrollment=None)
        self.assertCountEqual(["decorators", "schedule", "file_accesses", "file_paths"],
                              config.keys())  # no packs
        schedule = config["schedule"]
        self.assertCountEqual([INVENTORY_QUERY_NAME,
                               self.query_1_key,
                               self.query_2_key,
                               self.query_mbu_key],
                              schedule.keys())
        file_paths = config["file_paths"]
        self.assertCountEqual(file_paths.keys(),
                              [self.query_1_filepath_hash,
                               self.query_2_filepath_hash,
                               self.query_mbu_filepath_hash])
        for key, file_path in ((self.query_1_filepath_hash, self.query_1_filepath),
                               (self.query_2_filepath_hash, self.query_2_filepath),
                               (self.query_mbu_filepath_hash, self.query_mbu_filepath)):
            self.assertEqual(file_paths.get(key), [file_path])
        file_accesses = config["file_accesses"]
        self.assertEqual([self.query_2_filepath_hash], file_accesses)
