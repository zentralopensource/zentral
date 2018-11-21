from datetime import timedelta
from django.test import TestCase
from django.utils import timezone
from zentral.core.events import event_types
from zentral.core.events.base import EventMetadata
from zentral.core.probes.conf import all_probes
from zentral.core.probes.models import ProbeSource
from zentral.contrib.osquery.models import DistributedQueryProbeMachine, MAX_DISTRIBUTED_QUERY_AGE
from zentral.contrib.osquery.probes import OsqueryDistributedQueryProbe
from tests.inventory.utils import MockMetaMachine


payload_template = {
    "probe": {
        "name": "yo",
        "id": 42
    },
    "error": False,
    "result": [
        # TODO
    ]
}


def build_osquery_distributed_query_result_event(query_name, query_id):
    OsqueryDistributedQueryResult = event_types["osquery_distributed_query_result"]
    payload = payload_template.copy()
    payload["probe"]["name"] = query_name
    payload["probe"]["id"] = query_id
    return OsqueryDistributedQueryResult(EventMetadata(machine_serial_number="YO",
                                                       event_type=OsqueryDistributedQueryResult.event_type),
                                         payload)


class OsqueryDistributedQueryProbeTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # probe 1, users
        cls.query_1 = "select * from users"
        cls.probe_source_1 = ProbeSource.objects.create(
            model="OsqueryDistributedQueryProbe",
            name="osquery distributed query 1",
            status=ProbeSource.ACTIVE,
            body={"distributed_query": cls.query_1}
        )
        cls.probe_1 = cls.probe_source_1.load()
        cls.query_1_key = "dq_{}".format(cls.probe_1.pk)
        # probe 2, processes
        cls.query_2 = "select * from processes"
        cls.probe_source_2 = ProbeSource.objects.create(
            model="OsqueryDistributedQueryProbe",
            name="osquery distributed query 2",
            status=ProbeSource.ACTIVE,
            body={"distributed_query": cls.query_2}
        )
        cls.probe_2 = cls.probe_source_2.load()
        cls.query_2_key = "dq_{}".format(cls.probe_2.pk)
        # probe windows, system_info
        cls.query_windows = "select * from system_info"
        cls.probe_source_windows = ProbeSource.objects.create(
            model="OsqueryDistributedQueryProbe",
            name="osquery probe windows",
            status=ProbeSource.ACTIVE,
            body={"filters": {"inventory": [{"platforms": ["WINDOWS"]}]},
                  "distributed_query": cls.query_windows}
        )
        cls.probe_windows = cls.probe_source_windows.load()
        cls.query_windows_key = "dq_{}".format(cls.probe_windows.pk)
        # clear
        all_probes.clear()

    def test_probes(self):
        for probe in (self.probe_1,
                      self.probe_2,
                      self.probe_windows):
            self.assertTrue(isinstance(probe, OsqueryDistributedQueryProbe))

    def test_probes_metadata_filters(self):
        for probe in (self.probe_1,
                      self.probe_2,
                      self.probe_windows):
            self.assertEqual(len(probe.metadata_filters), 1)
            metadata_filter = probe.metadata_filters[0]
            self.assertEqual(metadata_filter.event_types, set(["osquery_distributed_query_result"]))
            self.assertEqual(metadata_filter.event_tags, set([]))

    def test_all_probes(self):
        probes = list(all_probes.class_filter(OsqueryDistributedQueryProbe))
        self.assertEqual(len(probes), 3)

    def test_probe_sources_event_type(self):
        for probe_source in (self.probe_source_1,
                             self.probe_source_2,
                             self.probe_source_windows):
            self.assertEqual(probe_source.event_types, ["osquery_distributed_query_result"])

    def test_probes_test_event(self):
        default_machine = MockMetaMachine([], [], None, None)
        windows = MockMetaMachine([1], [1], "WINDOWS", None)
        tests = (
          # wrong probe id
          (self.probe_1, self.probe_2.pk, default_machine, False),
          (self.probe_2, self.probe_1.pk, windows, False),
          (self.probe_windows, self.probe_1.pk, windows, False),
          # ok
          (self.probe_1, self.probe_1.pk, default_machine, True),
          (self.probe_2, self.probe_2.pk, windows, True),
          # windows
          (self.probe_windows, self.probe_windows.pk, default_machine, False),
          (self.probe_windows, self.probe_windows.pk, windows, True),
        )
        for probe, query_id, machine, result in tests:
            event = build_osquery_distributed_query_result_event("NAME NOT TESTED", query_id)
            event.metadata.machine = machine  # hack
            self.assertEqual(probe.test_event(event), result)

    def test_extra_event_search_dict(self):
        for probe in (self.probe_1,
                      self.probe_2,
                      self.probe_windows):
            sd = probe.get_extra_event_search_dict()
            self.assertEqual(sd["event_type"], "osquery_distributed_query_result")
            self.assertTrue(sd["probe.id"], probe.pk)

    def test_default_machine_distributed_queries(self):
        default_machine = MockMetaMachine([], [], None, None, serial_number="MSN1")
        # simulate all_probes sync
        all_probes.clear()
        queries = DistributedQueryProbeMachine.objects.new_queries_for_machine(default_machine)
        self.assertEqual(len(queries), 2)
        for key, query in ((self.query_1_key, self.query_1),
                           (self.query_2_key, self.query_2)):
            self.assertEqual(queries[key], query)
        # simulate all_probes sync
        all_probes.clear()
        extra_queries = DistributedQueryProbeMachine.objects.new_queries_for_machine(default_machine)
        self.assertEqual(extra_queries, {})

    def test_windows_machine_distributed_queries(self):
        windows_machine = MockMetaMachine([], [], "WINDOWS", None, serial_number="MSN2")
        # simulate all_probes sync
        all_probes.clear()
        queries = DistributedQueryProbeMachine.objects.new_queries_for_machine(windows_machine)
        self.assertEqual(len(queries), 3)
        for key, query in ((self.query_1_key, self.query_1),
                           (self.query_2_key, self.query_2),
                           (self.query_windows_key, self.query_windows)):
            self.assertEqual(queries[key], query)
        # simulate all_probes sync
        all_probes.clear()
        extra_queries = DistributedQueryProbeMachine.objects.new_queries_for_machine(windows_machine)
        self.assertEqual(extra_queries, {})

    def test_default_machine_older_distributed_queries(self):
        default_machine = MockMetaMachine([], [], None, None, serial_number="MSN3")
        # simulate all_probes sync
        all_probes.clear()
        # consume all queries
        queries = DistributedQueryProbeMachine.objects.new_queries_for_machine(default_machine)
        self.assertEqual(len(queries), 2)
        queries = DistributedQueryProbeMachine.objects.new_queries_for_machine(default_machine)
        self.assertEqual(len(queries), 0)
        # make a query that is one hour too old
        probe_source_too_old = ProbeSource.objects.create(
            model="OsqueryDistributedQueryProbe",
            name="QUERY TOO OLD",
            status=ProbeSource.ACTIVE,
            body={"distributed_query": "SELECT 'QUERY TOO OLD';"},
        )
        # simulate all_probes sync
        all_probes.clear()
        probe_source_too_old.created_at = timezone.now() - MAX_DISTRIBUTED_QUERY_AGE - timedelta(hours=1)
        probe_source_too_old.save()
        queries = DistributedQueryProbeMachine.objects.new_queries_for_machine(default_machine)
        # it's not there
        self.assertEqual(len(queries), 0)
        # make a query that is one hour younger than the limit
        probe_source_ok = ProbeSource.objects.create(
            model="OsqueryDistributedQueryProbe",
            name="QUERY OK",
            status=ProbeSource.ACTIVE,
            body={"distributed_query": "SELECT 'QUERY OK';"},
        )
        probe_source_ok.created_at = timezone.now() - MAX_DISTRIBUTED_QUERY_AGE + timedelta(hours=1)
        probe_source_ok.save()
        # simulate all_probes sync
        all_probes.clear()
        # it's there
        queries = DistributedQueryProbeMachine.objects.new_queries_for_machine(default_machine)
        self.assertEqual(len(queries), 1)
        self.assertEqual(queries["dq_{}".format(probe_source_ok.pk)], "SELECT 'QUERY OK';")
