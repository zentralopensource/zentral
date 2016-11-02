import re
from django.test import TestCase
from zentral.core.events import event_types
from zentral.core.events.base import EventMetadata
from zentral.core.probes.conf import all_probes
from zentral.core.probes.models import ProbeSource
from zentral.contrib.osquery.conf import DEFAULT_ZENTRAL_INVENTORY_QUERY, build_osquery_conf
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
        cls.query_1 = {"query": "select * from processes",
                       "interval": 123}
        cls.query_1_key = "osquery-probe-1_00adca42"
        cls.probe_source_1 = ProbeSource.objects.create(
            model="OsqueryProbe",
            name="osquery probe 1",
            status=ProbeSource.ACTIVE,
            body={"queries": [cls.query_1]}
        )
        cls.probe_1 = cls.probe_source_1.load()
        cls.query_2 = {"query": "select * from users"}
        cls.query_2_key = "osquery-probe-2_19206bc4"
        cls.probe_source_2 = ProbeSource.objects.create(
            model="OsqueryProbe",
            name="osquery probe 2",
            status=ProbeSource.ACTIVE,
            body={"queries": [cls.query_2]}
        )
        cls.probe_2 = cls.probe_source_2.load()
        cls.query_windows = {"query": "select * from users"}
        cls.query_windows_key = "osquery-probe-windows_19206bc4"
        cls.probe_source_windows = ProbeSource.objects.create(
            model="OsqueryProbe",
            name="osquery probe windows",
            status=ProbeSource.ACTIVE,
            body={"filters": {"inventory": [{"platforms": ["WINDOWS"]}]},
                  "queries": [cls.query_windows]}
        )
        cls.probe_windows = cls.probe_source_windows.load()
        all_probes.clear()

    def test_probes(self):
        for probe in (self.probe_1,
                      self.probe_2,
                      self.probe_windows):
            self.assertTrue(isinstance(probe, OsqueryProbe))

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
          (self.probe_1, self.query_2_key, default_machine, False),
          (self.probe_2, self.query_1_key, windows, False),
          (self.probe_windows, self.query_1_key, windows, False),
          # ok
          (self.probe_1, self.query_1_key, default_machine, True),
          (self.probe_2, self.query_2_key, windows, True),
          # windows
          (self.probe_windows, self.query_windows_key, default_machine, False),
          (self.probe_windows, self.query_windows_key, windows, True),
        )
        for probe, query_name, machine, result in tests:
            event = build_osquery_result_event(query_name)
            event.metadata.machine = machine  # hack
            self.assertEqual(probe.test_event(event), result)

    def test_scheduled_queries(self):
        for probe, key in ((self.probe_1, self.query_1_key),
                           (self.probe_2, self.query_2_key),
                           (self.probe_windows, self.query_windows_key)):
            self.assertTrue(isinstance(probe.scheduled_queries, dict))
            self.assertTrue(key in probe.scheduled_queries)
            for osquery_query in probe.iter_scheduled_queries():
                self.assertTrue(osquery_query.name in probe.scheduled_queries)

    def test_extra_event_search_dict(self):
        for probe, key in ((self.probe_1, self.query_1_key),
                           (self.probe_2, self.query_2_key),
                           (self.probe_windows, self.query_windows_key)):
            sd = probe.get_extra_event_search_dict()
            self.assertEqual(sd["event_type"], "osquery_result")
            self.assertTrue(re.match(sd["name__regexp"], key) is not None)
            for osquery_query in probe.iter_scheduled_queries():
                self.assertTrue(re.match(sd["name__regexp"], osquery_query.name) is not None)

    def test_osquery_conf(self):
        # default machine has a subset of the queries
        default_machine = MockMetaMachine([], [], None, None)
        config = build_osquery_conf(default_machine)
        schedule = config["schedule"]
        self.assertTrue(DEFAULT_ZENTRAL_INVENTORY_QUERY in schedule)
        schedule.pop(DEFAULT_ZENTRAL_INVENTORY_QUERY)
        self.assertEqual(len(schedule), 2)

        # windows has all the queries
        windows = MockMetaMachine([1], [1], "WINDOWS", None)
        config = build_osquery_conf(windows)
        schedule = config["schedule"]
        self.assertTrue(DEFAULT_ZENTRAL_INVENTORY_QUERY in schedule)
        schedule.pop(DEFAULT_ZENTRAL_INVENTORY_QUERY)
        self.assertEqual(len(schedule), 3)
