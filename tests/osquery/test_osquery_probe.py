import re
from django.test import TestCase
from zentral.core.events import event_types
from zentral.core.events.base import EventMetadata
from zentral.core.probes.conf import all_probes
from zentral.core.probes.models import ProbeSource
from zentral.contrib.osquery.conf import INVENTORY_QUERY_NAME, build_osquery_conf
from zentral.contrib.osquery.probes import OsqueryProbe
from tests.inventory.utils import MockMetaMachine


payload_template = {
    "action": "added",
    "hostIdentifier": "Yo.local",
    "calendarTime": "Mon Nov 28 21:33:35 2016 UTC",
    "columns": {
        "sparkle_version": "1.5 Beta 6",
        "bundle_id": "com.appthology.Thetis",
        "app_name": "Thetis.app",
        "feed_url": "http://www.appthology.net/apps/thetis/appcast.xml",
        "app_path": "/Volumes/YoSSD/Applications/Thetis.app"
    },
    "unixTime": "1480368815"
}


def build_osquery_result_event(query_name):
    OsqueryResult = event_types["osquery_result"]
    payload = payload_template.copy()
    payload["name"] = query_name
    return OsqueryResult(EventMetadata(machine_serial_number="YO",
                                       event_type=OsqueryResult.event_type),
                         payload)


class OsqueryProbeTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # schedule
        # probe 1, all machines, schedule
        cls.query_1 = {"query": "select * from processes",
                       "interval": 123}
        cls.query_1_key = "osquery-probe-1_00adca42"
        cls.query_1_result_name = cls.query_1_key
        cls.probe_source_1 = ProbeSource.objects.create(
            model="OsqueryProbe",
            name="osquery probe 1",
            status=ProbeSource.ACTIVE,
            body={"queries": [cls.query_1]}
        )
        cls.probe_1 = cls.probe_source_1.load()
        # query pack
        cls.query_pack_discovery = [
            "select pid from processes where name = 'foobar';",
            "select count(*) from users where username like 'www%';"
        ]
        cls.query_pack_key = "05f720ae"
        # probe 2, all machines, query pack
        cls.query_2 = {"query": "select * from users"}
        cls.query_2_key = "osquery-probe-2_19206bc4"
        cls.query_2_result_name = "pack_05f720ae_osquery-probe-2_19206bc4"
        cls.probe_source_2 = ProbeSource.objects.create(
            model="OsqueryProbe",
            name="osquery probe 2",
            status=ProbeSource.ACTIVE,
            body={"queries": [cls.query_2],
                  "discovery": cls.query_pack_discovery}
        )
        cls.probe_2 = cls.probe_source_2.load()
        # probe windows, windows machines, query pack
        cls.query_windows = {"query": "select * from users"}
        cls.query_windows_key = "osquery-probe-windows_19206bc4"
        cls.query_windows_result_name = "pack_05f720ae_osquery-probe-windows_19206bc4"
        cls.probe_source_windows = ProbeSource.objects.create(
            model="OsqueryProbe",
            name="osquery probe windows",
            status=ProbeSource.ACTIVE,
            body={"filters": {"inventory": [{"platforms": ["WINDOWS"]}]},
                  "queries": [cls.query_windows],
                  "discovery": cls.query_pack_discovery[::-1]}  # reversed !
        )
        cls.probe_windows = cls.probe_source_windows.load()
        all_probes.clear()

    def test_bad_version(self):
        ps = ProbeSource.objects.create(
            model="OsqueryProbe",
            name="bad version",
            status=ProbeSource.ACTIVE,
            body={"queries": [{"query": "select * from users;",
                               "version": "bad version"}]}
        )
        self.assertEqual(ps.status, ProbeSource.INACTIVE)
        probe = ps.load()
        self.assertEqual(probe.loaded, False)
        self.assertIn("version", probe.syntax_errors["queries"][0])

    def test_probes(self):
        for probe in (self.probe_1,
                      self.probe_2,
                      self.probe_windows):
            self.assertTrue(isinstance(probe, OsqueryProbe))

    def test_probe_discovery(self):
        for probe, discovery in ((self.probe_1, []),
                                 (self.probe_2, self.query_pack_discovery),
                                 (self.probe_windows, self.query_pack_discovery)):
            self.assertCountEqual(probe.discovery, discovery)

    def test_probes_metadata_filters(self):
        for probe in (self.probe_1,
                      self.probe_2,
                      self.probe_windows):
            self.assertEqual(len(probe.metadata_filters), 1)
            metadata_filter = probe.metadata_filters[0]
            self.assertEqual(metadata_filter.event_types, set(["osquery_result"]))
            self.assertEqual(metadata_filter.event_tags, set([]))

    def test_all_probes(self):
        probes = list(all_probes.model_filter("OsqueryProbe"))
        self.assertEqual(len(probes), 3)

    def test_probe_sources_event_type(self):
        for probe_source in (self.probe_source_1,
                             self.probe_source_2,
                             self.probe_source_windows):
            self.assertEqual(probe_source.event_types, ["osquery_result"])

    def test_probes_test_event(self):
        default_machine = MockMetaMachine([], [], None, None)
        windows = MockMetaMachine([1], [1], "WINDOWS", None)
        tests = (
          # wrong hash
          (self.probe_1, self.query_2_result_name, default_machine, False),
          (self.probe_2, self.query_1_result_name, windows, False),
          (self.probe_windows, self.query_1_result_name, windows, False),
          # ok
          (self.probe_1, self.query_1_result_name, default_machine, True),
          (self.probe_2, self.query_2_result_name, windows, True),
          # windows
          (self.probe_windows, self.query_windows_result_name, default_machine, False),
          (self.probe_windows, self.query_windows_result_name, windows, True),
        )
        for probe, query_name, machine, result in tests:
            event = build_osquery_result_event(query_name)
            event.metadata.machine = machine  # hack
            self.assertEqual(probe.test_event(event), result)

    def test_scheduled_queries(self):
        for probe, key in ((self.probe_1, self.query_1_result_name),
                           (self.probe_2, self.query_2_result_name),
                           (self.probe_windows, self.query_windows_result_name)):
            self.assertTrue(isinstance(probe.scheduled_queries, dict))
            self.assertTrue(key in probe.scheduled_queries)
            for osquery_query in probe.iter_scheduled_queries():
                self.assertIn(osquery_query.result_name, probe.scheduled_queries)

    def test_extra_event_search_dict(self):
        for probe, result_name in ((self.probe_1, self.query_1_result_name),
                                   (self.probe_2, self.query_2_result_name),
                                   (self.probe_windows, self.query_windows_result_name)):
            sd = probe.get_extra_event_search_dict()
            self.assertEqual(sd["event_type"], "osquery_result")
            self.assertEqual([q.result_name for q in probe.iter_scheduled_queries()],
                             [result_name])
            self.assertTrue(re.match(sd["name__regexp"], result_name) is not None)

    def test_osquery_conf(self):
        # default machine has a subset of the queries
        default_machine = MockMetaMachine([], [], None, None)
        config = build_osquery_conf(default_machine, enrollment=None)
        # schedule with query 1
        schedule = config["schedule"]
        self.assertIsInstance(schedule, dict)
        self.assertCountEqual([INVENTORY_QUERY_NAME, self.query_1_key], schedule.keys())
        # 1 pack with query 2
        packs = config["packs"]
        self.assertIsInstance(packs, dict)
        self.assertCountEqual([self.query_pack_key], packs.keys())
        pack = packs[self.query_pack_key]
        self.assertIsInstance(pack, dict)
        self.assertCountEqual(["discovery", "queries"], pack.keys())
        self.assertCountEqual(pack["discovery"], self.query_pack_discovery)
        pack_queries = pack["queries"]
        self.assertCountEqual([self.query_2_key], pack_queries.keys())

        # windows has all the queries
        windows = MockMetaMachine([1], [1], "WINDOWS", None)
        config = build_osquery_conf(windows, enrollment=None)
        # schedule with query 1
        schedule = config["schedule"]
        self.assertIsInstance(schedule, dict)
        self.assertCountEqual([INVENTORY_QUERY_NAME, self.query_1_key], schedule.keys())
        # 1 pack with query 2 and query windows
        packs = config["packs"]
        self.assertIsInstance(packs, dict)
        self.assertCountEqual([self.query_pack_key], packs.keys())
        pack = packs[self.query_pack_key]
        self.assertIsInstance(pack, dict)
        self.assertCountEqual(["discovery", "queries"], pack.keys())
        self.assertCountEqual(pack["discovery"], self.query_pack_discovery)
        pack_queries = pack["queries"]
        self.assertCountEqual([self.query_2_key, self.query_windows_key], pack_queries.keys())
