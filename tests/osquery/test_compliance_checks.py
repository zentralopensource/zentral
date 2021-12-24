from datetime import datetime
from django.test import TestCase
from django.utils.crypto import get_random_string
from django.utils.text import slugify
from zentral.core.compliance_checks.models import MachineStatus, Status
from zentral.contrib.osquery.compliance_checks import ComplianceCheckStatusAggregator, sync_query_compliance_check
from zentral.contrib.osquery.events import OsqueryCheckStatusUpdated
from zentral.contrib.osquery.models import DistributedQuery, Pack, PackQuery, Query


class OsqueryComplianceChecksTestCase(TestCase):
    def _force_pack(self):
        name = get_random_string()
        return Pack.objects.create(name=name, slug=slugify(name))

    def _force_query(self, force_pack=False, force_compliance_check=False, force_distributed_query=False):
        if force_compliance_check:
            sql = "select 'OK' as ztl_status;"
        else:
            sql = "select 1 from processes;"
        query = Query.objects.create(name=get_random_string(), sql=sql)
        pack = None
        if force_pack:
            pack = self._force_pack()
            PackQuery.objects.create(pack=pack, query=query, interval=12983,
                                     slug=slugify(query.name),
                                     log_removed_actions=False, snapshot_mode=force_compliance_check)
        sync_query_compliance_check(query, force_compliance_check)
        distributed_query = None
        if force_distributed_query:
            distributed_query = DistributedQuery.objects.create(
                query=query,
                query_version=query.version,
                sql=query.sql,
                valid_from=datetime.utcnow()
            )
        return query, pack, distributed_query

    def test_no_compliance_check(self):
        query, _, _ = self._force_query(force_pack=True)
        serial_number = get_random_string()
        cc_status_agg = ComplianceCheckStatusAggregator(serial_number)
        cc_status_agg.add_result(query.pk, query.version, datetime.utcnow(), [{"ztl_status": Status.OK.value}])
        events = list(cc_status_agg.commit())
        self.assertEqual(len(events), 0)
        ms_qs = MachineStatus.objects.filter(compliance_check=query.compliance_check, serial_number=serial_number)
        self.assertEqual(ms_qs.count(), 0)

    def test_scheduled_compliance_check_one_ok_tuple(self):
        query, pack, _ = self._force_query(force_pack=True, force_compliance_check=True)
        compliance_check = query.compliance_check
        serial_number = get_random_string()
        cc_status_agg = ComplianceCheckStatusAggregator(serial_number)
        status_time = datetime(2021, 12, 25)
        cc_status_agg.add_result(query.pk, query.version, status_time, [{"ztl_status": Status.OK.name}])
        events = list(cc_status_agg.commit())
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, OsqueryCheckStatusUpdated)
        self.assertEqual(event.metadata.created_at, status_time)
        self.assertEqual(event.payload["pk"], compliance_check.pk)
        self.assertEqual(event.payload["version"], query.version)
        self.assertEqual(event.payload["version"], compliance_check.version)
        self.assertEqual(event.payload["osquery_query"], {"pk": query.pk})
        self.assertEqual(event.payload["osquery_pack"], {"pk": pack.pk, "name": pack.name})
        self.assertIsNone(event.payload.get("osquery_run"))
        self.assertEqual(event.payload["status"], Status.OK.name)
        self.assertIsNone(event.payload.get("previous_status"))
        self.assertEqual(event.get_linked_objects_keys(),
                         {"compliance_check": [(compliance_check.pk,)],
                          "osquery_query": [(query.pk,)],
                          "osquery_pack": [(pack.pk,)]})
        ms_qs = MachineStatus.objects.filter(compliance_check=compliance_check, serial_number=serial_number)
        self.assertEqual(ms_qs.count(), 1)
        ms = ms_qs.first()
        self.assertEqual(ms.compliance_check_version, compliance_check.version)
        self.assertEqual(ms.status, Status.OK.value)
        self.assertEqual(ms.status_time, status_time)

    def test_one_time_compliance_check_one_ok_tuple(self):
        query, _, distributed_query = self._force_query(
            force_pack=True,
            force_compliance_check=True,
            force_distributed_query=True
        )
        compliance_check = query.compliance_check
        serial_number = get_random_string()
        cc_status_agg = ComplianceCheckStatusAggregator(serial_number)
        status_time = datetime.utcnow()
        cc_status_agg.add_result(
            query.pk, query.version, status_time, [{"ztl_status": Status.OK.name}], distributed_query.pk
        )
        events = list(cc_status_agg.commit())
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, OsqueryCheckStatusUpdated)
        self.assertEqual(event.payload["pk"], compliance_check.pk)
        self.assertEqual(event.payload["version"], query.version)
        self.assertEqual(event.payload["version"], compliance_check.version)
        self.assertEqual(event.payload["osquery_query"], {"pk": query.pk})
        self.assertIsNone(event.payload.get("osquery_pack"))
        self.assertEqual(event.payload["osquery_run"], {"pk": distributed_query.pk})
        self.assertEqual(event.payload["status"], Status.OK.name)
        self.assertIsNone(event.payload.get("previous_status"))
        self.assertEqual(event.get_linked_objects_keys(),
                         {"compliance_check": [(compliance_check.pk,)],
                          "osquery_query": [(query.pk,)],
                          "osquery_run": [(distributed_query.pk,)]})
        ms_qs = MachineStatus.objects.filter(compliance_check=compliance_check, serial_number=serial_number)
        self.assertEqual(ms_qs.count(), 1)
        ms = ms_qs.first()
        self.assertEqual(ms.compliance_check_version, compliance_check.version)
        self.assertEqual(ms.status, Status.OK.value)
        self.assertEqual(ms.status_time, status_time)

    def test_scheduled_compliance_check_no_tuple(self):
        query, _, _ = self._force_query(force_pack=True, force_compliance_check=True)
        serial_number = get_random_string()
        cc_status_agg = ComplianceCheckStatusAggregator(serial_number)
        status_time = datetime.utcnow()
        cc_status_agg.add_result(query.pk, query.version, status_time, [])
        events = list(cc_status_agg.commit())
        self.assertEqual(len(events), 1)
        ms_qs = MachineStatus.objects.filter(compliance_check=query.compliance_check, serial_number=serial_number)
        self.assertEqual(ms_qs.count(), 1)
        ms = ms_qs.first()
        self.assertEqual(ms.compliance_check_version, query.compliance_check.version)
        self.assertEqual(ms.status, Status.UNKNOWN.value)
        self.assertEqual(ms.status_time, status_time)

    def test_scheduled_compliance_check_worse_missing_unknown_tuple(self):
        query, _, _ = self._force_query(force_pack=True, force_compliance_check=True)
        serial_number = get_random_string()
        cc_status_agg = ComplianceCheckStatusAggregator(serial_number)
        status_time = datetime.utcnow()
        cc_status_agg.add_result(query.pk, query.version, status_time,
                                 [{"ztl_status": Status.OK.name},
                                  {}])
        events = list(cc_status_agg.commit())
        self.assertEqual(len(events), 1)
        ms_qs = MachineStatus.objects.filter(compliance_check=query.compliance_check, serial_number=serial_number)
        self.assertEqual(ms_qs.count(), 1)
        ms = ms_qs.first()
        self.assertEqual(ms.compliance_check_version, query.compliance_check.version)
        self.assertEqual(ms.status, Status.UNKNOWN.value)
        self.assertEqual(ms.status_time, status_time)

    def test_scheduled_compliance_check_worse_bad_unknown_tuple(self):
        query, _, _ = self._force_query(force_pack=True, force_compliance_check=True)
        serial_number = get_random_string()
        cc_status_agg = ComplianceCheckStatusAggregator(serial_number)
        status_time = datetime.utcnow()
        cc_status_agg.add_result(query.pk, query.version, status_time,
                                 [{"ztl_status": Status.OK.name},
                                  {"ztl_status": "_NOT_A_VALID_STATUS"}])
        events = list(cc_status_agg.commit())
        self.assertEqual(len(events), 1)
        ms_qs = MachineStatus.objects.filter(compliance_check=query.compliance_check, serial_number=serial_number)
        self.assertEqual(ms_qs.count(), 1)
        ms = ms_qs.first()
        self.assertEqual(ms.compliance_check_version, query.compliance_check.version)
        self.assertEqual(ms.status, Status.UNKNOWN.value)
        self.assertEqual(ms.status_time, status_time)

    def test_scheduled_compliance_check_worse_failed_tuple(self):
        query, _, _ = self._force_query(force_pack=True, force_compliance_check=True)
        serial_number = get_random_string()
        cc_status_agg = ComplianceCheckStatusAggregator(serial_number)
        status_time = datetime.utcnow()
        cc_status_agg.add_result(query.pk, query.version, status_time,
                                 [{"ztl_status": Status.OK.name},
                                  {"ztl_status": Status.FAILED.name}])
        events = list(cc_status_agg.commit())
        self.assertEqual(len(events), 1)
        ms_qs = MachineStatus.objects.filter(compliance_check=query.compliance_check, serial_number=serial_number)
        self.assertEqual(ms_qs.count(), 1)
        ms = ms_qs.first()
        self.assertEqual(ms.compliance_check_version, query.compliance_check.version)
        self.assertEqual(ms.status, Status.FAILED.value)
        self.assertEqual(ms.status_time, status_time)

    def test_scheduled_compliance_check_two_tuples_last_wins(self):
        query, _, _ = self._force_query(force_pack=True, force_compliance_check=True)
        serial_number = get_random_string()
        cc_status_agg = ComplianceCheckStatusAggregator(serial_number)
        cc_status_agg.add_result(query.pk, query.version, datetime(2001, 1, 1), [{"ztl_status": Status.FAILED.name}])
        status_time = datetime.utcnow()
        cc_status_agg.add_result(query.pk, query.version, status_time, [{"ztl_status": Status.OK.name}])
        events = list(cc_status_agg.commit())
        self.assertEqual(len(events), 1)
        ms_qs = MachineStatus.objects.filter(compliance_check=query.compliance_check, serial_number=serial_number)
        self.assertEqual(ms_qs.count(), 1)
        ms = ms_qs.first()
        self.assertEqual(ms.compliance_check_version, query.compliance_check.version)
        self.assertEqual(ms.status, Status.OK.value)
        self.assertEqual(ms.status_time, status_time)

    def test_scheduled_compliance_check_two_tuples_reversed_last_wins(self):
        query, _, _ = self._force_query(force_pack=True, force_compliance_check=True)
        serial_number = get_random_string()
        cc_status_agg = ComplianceCheckStatusAggregator(serial_number)
        status_time = datetime.utcnow()
        cc_status_agg.add_result(query.pk, query.version, status_time, [{"ztl_status": Status.OK.name}])
        cc_status_agg.add_result(query.pk, query.version, datetime(2001, 1, 1), [{"ztl_status": Status.FAILED.name}])
        events = list(cc_status_agg.commit())
        self.assertEqual(len(events), 1)
        ms_qs = MachineStatus.objects.filter(compliance_check=query.compliance_check, serial_number=serial_number)
        self.assertEqual(ms_qs.count(), 1)
        ms = ms_qs.first()
        self.assertEqual(ms.compliance_check_version, query.compliance_check.version)
        self.assertEqual(ms.status, Status.OK.value)
        self.assertEqual(ms.status_time, status_time)

    def test_scheduled_compliance_check_one_outdated_failed_tuple(self):
        query, _, _ = self._force_query(force_pack=True, force_compliance_check=True)
        serial_number = get_random_string()
        status_time = datetime.utcnow()
        existing_ms = MachineStatus.objects.create(
            serial_number=serial_number,
            compliance_check=query.compliance_check,
            compliance_check_version=query.compliance_check.version,
            status=Status.OK.value,
            status_time=status_time
        )
        cc_status_agg = ComplianceCheckStatusAggregator(serial_number)
        cc_status_agg.add_result(query.pk, query.version, datetime(2001, 1, 1), [{"ztl_status": Status.FAILED.name}])
        events = list(cc_status_agg.commit())
        self.assertEqual(len(events), 0)
        ms_qs = MachineStatus.objects.filter(compliance_check=query.compliance_check, serial_number=serial_number)
        self.assertEqual(ms_qs.count(), 1)
        ms = ms_qs.first()
        self.assertEqual(ms, existing_ms)
        self.assertEqual(ms.compliance_check_version, query.compliance_check.version)
        self.assertEqual(ms.status, Status.OK.value)
        self.assertEqual(ms.status_time, status_time)

    def test_scheduled_compliance_check_one_outdated_version_failed_tuple(self):
        query, _, _ = self._force_query(force_pack=True, force_compliance_check=True)
        query.version = 127
        query.save()
        serial_number = get_random_string()
        cc_status_agg = ComplianceCheckStatusAggregator(serial_number)
        cc_status_agg.add_result(query.pk, 1, datetime.utcnow(), [{"ztl_status": Status.FAILED.name}])
        events = list(cc_status_agg.commit())
        self.assertEqual(len(events), 0)
        ms_qs = MachineStatus.objects.filter(compliance_check=query.compliance_check, serial_number=serial_number)
        self.assertEqual(ms_qs.count(), 0)

    def test_scheduled_compliance_check_one_ok_tuple_no_update(self):
        query, _, _ = self._force_query(force_pack=True, force_compliance_check=True)
        serial_number = get_random_string()
        cc_status_agg = ComplianceCheckStatusAggregator(serial_number)
        existing_ms = MachineStatus.objects.create(
            serial_number=serial_number,
            compliance_check=query.compliance_check,
            compliance_check_version=query.compliance_check.version,
            status=Status.OK.value,
            status_time=datetime(2001, 1, 1)
        )
        status_time = datetime.utcnow()
        cc_status_agg.add_result(query.pk, query.version, status_time, [{"ztl_status": Status.OK.name}])
        events = list(cc_status_agg.commit())
        self.assertEqual(len(events), 0)
        ms_qs = MachineStatus.objects.filter(compliance_check=query.compliance_check, serial_number=serial_number)
        self.assertEqual(ms_qs.count(), 1)
        ms = ms_qs.first()
        self.assertEqual(ms, existing_ms)
        self.assertEqual(ms.compliance_check_version, query.compliance_check.version)
        self.assertEqual(ms.status, Status.OK.value)
        self.assertEqual(ms.status_time, status_time)

    def test_scheduled_compliance_check_one_ok_tuple_update(self):
        query, _, _ = self._force_query(force_pack=True, force_compliance_check=True)
        serial_number = get_random_string()
        cc_status_agg = ComplianceCheckStatusAggregator(serial_number)
        existing_ms = MachineStatus.objects.create(
            serial_number=serial_number,
            compliance_check=query.compliance_check,
            compliance_check_version=query.compliance_check.version,
            status=Status.OK.value,
            status_time=datetime(2001, 1, 1)
        )
        status_time = datetime.utcnow()
        cc_status_agg.add_result(query.pk, query.version, status_time, [{"ztl_status": Status.FAILED.name}])
        events = list(cc_status_agg.commit())
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.payload["status"], Status.FAILED.name)
        self.assertEqual(event.payload["previous_status"], Status.OK.name)
        ms_qs = MachineStatus.objects.filter(compliance_check=query.compliance_check, serial_number=serial_number)
        self.assertEqual(ms_qs.count(), 1)
        ms = ms_qs.first()
        self.assertEqual(ms, existing_ms)
        self.assertEqual(ms.compliance_check_version, query.compliance_check.version)
        self.assertEqual(ms.status, Status.FAILED.value)
        self.assertEqual(ms.status_time, status_time)

    def test_scheduled_compliance_check_one_ok_one_failed_tuple(self):
        query1, _, _ = self._force_query(force_pack=True, force_compliance_check=True)
        query2, _, _ = self._force_query(force_pack=True, force_compliance_check=True)
        serial_number = get_random_string()
        cc_status_agg = ComplianceCheckStatusAggregator(serial_number)
        status_time1 = datetime.utcnow()
        status_time2 = datetime.utcnow()
        cc_status_agg.add_result(query1.pk, query1.version, status_time1, [{"ztl_status": Status.OK.name}])
        cc_status_agg.add_result(query2.pk, query2.version, status_time2, [{"ztl_status": Status.FAILED.name}])
        events = list(cc_status_agg.commit())
        self.assertEqual(len(events), 2)
        ms_qs1 = MachineStatus.objects.filter(compliance_check=query1.compliance_check, serial_number=serial_number)
        self.assertEqual(ms_qs1.count(), 1)
        ms_qs2 = MachineStatus.objects.filter(compliance_check=query2.compliance_check, serial_number=serial_number)
        self.assertEqual(ms_qs2.count(), 1)
        ms1 = ms_qs1.get(compliance_check=query1.compliance_check)
        self.assertEqual(ms1.compliance_check_version, query1.compliance_check.version)
        self.assertEqual(ms1.status, Status.OK.value)
        self.assertEqual(ms1.status_time, status_time1)
        ms2 = ms_qs2.get(compliance_check=query2.compliance_check)
        self.assertEqual(ms2.compliance_check_version, query2.compliance_check.version)
        self.assertEqual(ms2.status, Status.FAILED.value)
        self.assertEqual(ms2.status_time, status_time2)
