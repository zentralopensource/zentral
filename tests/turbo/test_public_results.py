from datetime import datetime
import json
from unittest.mock import patch
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MachineTag, Tag
from zentral.contrib.turbo.command_backends import CommandBackend
from zentral.contrib.turbo.events import (TurboMSCPCheckComplianceCheckStatusUpdated, TurboRequestEvent,
                                          TurboResultEvent, TurboScriptComplianceCheckStatusUpdated)
from zentral.contrib.turbo.models import Job, OneTimeJob, OneTimeJobMachine, RecurringJobMachine
from zentral.core.compliance_checks.events import MachineComplianceChangeEvent
from zentral.core.compliance_checks.models import MachineStatus, Status
from .utils import (TurboPublicTestCase, force_command, force_configuration, force_enrolled_machine,
                    force_mscp_check, force_one_time_job, force_recurring_job, force_script)


class TurboResultsPublicTestCase(TurboPublicTestCase):
    def _results(self, token, body):
        return self.client.post(
            reverse("turbo_public:results"),
            data=json.dumps(body),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}",
        )

    def _enrolled(self):
        configuration = force_configuration()
        enrollment, serial_number, token = force_enrolled_machine(
            configuration=configuration, meta_business_unit=self.mbu)
        return configuration, enrollment, serial_number, token

    @staticmethod
    def _result(schedule, version=None, status=None, exit_code=None, duration=0.1,
                at="2026-06-22T10:00:00Z"):
        # a result references its schedule (RecurringJob / OneTimeJob) by run.schedule_pk;
        # the top-level identity is the schedule's Job. run.mode echoes the schedule kind.
        job = schedule.job
        mode = "one_time" if isinstance(schedule, OneTimeJob) else "recurring"
        run = {"at": at, "duration": duration, "schedule_pk": str(schedule.pk), "mode": mode}
        result = {}
        if exit_code is not None:
            result["exit_code"] = exit_code
        if status is not None:
            result["status"] = status
        return {"kind": job.kind, "pk": str(job.pk),
                "version": job.version if version is None else version,
                "run": run, "result": result}

    # auth

    def test_results_unauthenticated(self):
        self.assertEqual(self.client.post(reverse("turbo_public:results")).status_code, 401)

    def test_results_empty_token_unauthenticated(self):
        response = self.client.post(reverse("turbo_public:results"), data="{}",
                                    content_type="application/json",
                                    HTTP_AUTHORIZATION="TurboEnrolledMachine ")
        self.assertEqual(response.status_code, 401)

    def test_results_invalid_json(self):
        _, _, _, token = self._enrolled()
        response = self.client.post(reverse("turbo_public:results"), data="not json",
                                    content_type="application/json",
                                    HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_json"})

    def test_results_non_object_body(self):
        _, _, _, token = self._enrolled()
        response = self.client.post(reverse("turbo_public:results"), data="[]",
                                    content_type="application/json",
                                    HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_json"})

    def test_results_non_list_results(self):
        _, _, _, token = self._enrolled()
        response = self._results(token, {"results": "garbage"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_results"})

    def test_results_malformed_entries_and_sub_objects_rejected(self):
        # non-object entries and a garbage run fail the wire schema and are rejected; the rest of the
        # batch is ingested
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        weird = self._result(recurring_job, status=300)
        weird["run"] = "garbage"
        body = {"results": [42, "no", weird, self._result(recurring_job, status=300)]}
        self.assertEqual(self._results(token, body).status_code, 200)
        machine_status = MachineStatus.objects.get(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number)
        self.assertEqual(machine_status.status, Status.FAILED.value)

    def test_results_invalid_entry_rejected(self):
        # an entry that does not validate against the wire schema (here a garbage version) is rejected
        # whole: nothing is scored, no ledger row is minted, it is absent from the acknowledgment, and
        # the request still succeeds
        configuration, _, serial_number, token = self._enrolled()
        recurring_job = force_recurring_job(configuration=configuration)
        result = self._result(recurring_job, exit_code=0, version="three")
        response = self._results(token, {"results": [result]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"accepted": [], "skipped": []})
        self.assertEqual(RecurringJobMachine.objects.filter(serial_number=serial_number).count(), 0)

    def test_results_garbage_outcome_fields_rejected(self):
        # exit_code / status are the fields the server scores on: an entry carrying a mistyped one is
        # rejected (the outcome dict itself stays open for future fields)
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        result = self._result(recurring_job)
        result["result"] = {"status": "failed"}
        self.assertEqual(self._results(token, {"results": [result]}).status_code, 200)
        self.assertFalse(MachineStatus.objects.filter(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number).exists())
        result = self._result(recurring_job)
        result["result"] = "garbage"   # not even an object
        self.assertEqual(self._results(token, {"results": [result]}).status_code, 200)
        self.assertFalse(MachineStatus.objects.filter(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number).exists())

    def test_results_response_acknowledges_entries(self):
        # the response always enumerates the accepted and skipped entries, keyed by (schedule_pk, at)
        # with at normalized to ISO-8601 UTC; the agent deduces the rejected ones from what is missing
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        good = self._result(recurring_job, status=0, at="2026-06-22T10:00:00Z")
        unknown = self._result(recurring_job, status=0, at="2026-06-22T11:00:00Z")
        unknown["run"]["schedule_pk"] = "1c1cc264-63c7-4aad-b6df-c5be1d5d6adc"  # no such schedule
        mismatch = self._result(recurring_job, status=0, at="2026-06-22T12:00:00Z")
        mismatch["kind"] = "script"
        invalid = self._result(recurring_job, status=0, version="three")
        response = self._results(token, {"results": [good, unknown, mismatch, invalid]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "accepted": [{"schedule_pk": str(recurring_job.pk), "at": "2026-06-22T10:00:00+00:00"}],
            "skipped": [{"schedule_pk": "1c1cc264-63c7-4aad-b6df-c5be1d5d6adc",
                         "at": "2026-06-22T11:00:00+00:00", "reason": "unknown_schedule"},
                        {"schedule_pk": str(recurring_job.pk),
                         "at": "2026-06-22T12:00:00+00:00", "reason": "kind_mismatch"}],
        })

    def test_results_unknown_mscp_status_ignored(self):
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        self.assertEqual(self._results(token, {"results": [self._result(recurring_job, status=999)]}).status_code, 200)
        self.assertFalse(MachineStatus.objects.filter(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number).exists())

    def test_results_pending_mscp_status_ignored(self):
        # PENDING (100) is a valid Status value but means "no row" — it must never be stored
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        self.assertEqual(
            self._results(token, {"results": [self._result(recurring_job, status=100)]}).status_code, 200)
        self.assertFalse(MachineStatus.objects.filter(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number).exists())

    def test_results_malformed_schedule_pk_skipped(self):
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        result = self._result(recurring_job, status=300)
        result["run"]["schedule_pk"] = "not-a-uuid"
        self.assertEqual(self._results(token, {"results": [result]}).status_code, 200)
        self.assertFalse(MachineStatus.objects.filter(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number).exists())

    def test_results_malformed_run_at_rejected(self):
        # a single unparseable run.at rejects that entry (logged), not the batch: the rest is ingested
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        good = force_mscp_check()
        good_job = force_recurring_job(configuration=configuration, job=good.job)
        bad = self._result(recurring_job, status=300)
        bad["run"]["at"] = "garbage"
        body = {"results": [bad, self._result(good_job, status=300)]}
        self.assertEqual(self._results(token, body).status_code, 200)
        # the malformed result was dropped
        self.assertFalse(MachineStatus.objects.filter(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number).exists())
        # the well-formed one in the same batch still landed
        self.assertTrue(MachineStatus.objects.filter(
            compliance_check=good.compliance_check, serial_number=serial_number).exists())

    def test_results_missing_run_at_rejected(self):
        # run.at is required: a result the server cannot time-stamp cannot be scored or close a
        # one-time gate, so the whole entry is rejected — nothing is half-ingested, and the agent can
        # deduce the rejection from the acknowledgment
        configuration, _, serial_number, token = self._enrolled()
        one_time_job = force_one_time_job(configuration=configuration)
        null_at = self._result(one_time_job, exit_code=0, at=None)
        absent_at = self._result(one_time_job, exit_code=0)
        del absent_at["run"]["at"]
        for result in (null_at, absent_at):
            response = self._results(token, {"results": [result]})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {"accepted": [], "skipped": []})
        self.assertEqual(OneTimeJobMachine.objects.filter(serial_number=serial_number).count(), 0)

    def test_results_query_count_constant_regardless_of_batch_size(self):
        # the batched ledger update must cost the same number of queries no matter how many results
        # the agent uploads. Plain scripts (no compliance check, no tag) so the count reflects only
        # the batched ledger writes, not the per-check compliance upserts in update_machine_statuses.
        configuration = force_configuration()
        recurring_jobs = [force_recurring_job(configuration=configuration) for _ in range(5)]

        def post_query_count(n):
            # a fresh machine each call, so every post is a first-contact creating its own ledger rows
            _, _, token = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
            body = {"results": [self._result(j, exit_code=0) for j in recurring_jobs[:n]]}
            with CaptureQueriesContext(connection) as ctx:
                self.assertEqual(self._results(token, body).status_code, 200)
            return len(ctx.captured_queries)

        post_query_count(1)  # warm process-level caches (content types, …) before measuring
        self.assertEqual(post_query_count(1), post_query_count(5))

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_results_query_count_constant_with_compliance_checks(self, post_event):
        # scoring a verdict dereferences definition.compliance_check; resolve_schedules must prefetch it
        # so a larger batch of compliance results does not add a per-result SELECT (events are mocked out
        # here so the count reflects only the ingest queries)
        configuration = force_configuration()
        jobs = [force_recurring_job(configuration=configuration, job=force_script(compliance_check=True).job)
                for _ in range(5)]

        def post_query_count(n):
            _, _, token = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
            body = {"results": [self._result(j, exit_code=0) for j in jobs[:n]]}
            with CaptureQueriesContext(connection) as ctx:
                self.assertEqual(self._results(token, body).status_code, 200)
            return len(ctx.captured_queries)

        post_query_count(1)  # warm process-level caches before measuring
        self.assertEqual(post_query_count(1), post_query_count(5))

    # mSCP — the agent's verdict is passed through

    def test_results_mscp_status(self):
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        body = {"results": [self._result(recurring_job, status=300)]}
        self.assertEqual(self._results(token, body).status_code, 200)
        machine_status = MachineStatus.objects.get(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number)
        self.assertEqual(machine_status.status, Status.FAILED.value)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_results_mscp_out_of_scope_not_stored(self, post_event):
        # status 400 (OUT_OF_SCOPE) is an asserted N/A: it is reported as a result event but never
        # stored as a MachineStatus, so no MachineComplianceChangeEvent fires either
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        body = {"results": [self._result(recurring_job, status=400)]}
        with self.captureOnCommitCallbacks(execute=True):
            self.assertEqual(self._results(token, body).status_code, 200)
        self.assertFalse(MachineStatus.objects.filter(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number).exists())
        compliance_events = [c.args[0] for c in post_event.call_args_list
                             if isinstance(c.args[0], MachineComplianceChangeEvent)]
        self.assertEqual(compliance_events, [])
        result_events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], TurboResultEvent)]
        self.assertEqual(len(result_events), 1)
        self.assertEqual(result_events[0].payload["result"]["status"], 400)

    def test_results_mscp_out_of_scope_prunes_stored_status(self):
        # a check that was OK and now reports N/A drops its stored status (matches munki)
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        self.assertEqual(self._results(token, {"results": [self._result(recurring_job, status=0)]}).status_code, 200)
        self.assertTrue(MachineStatus.objects.filter(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number).exists())
        self.assertEqual(self._results(token, {"results": [self._result(recurring_job, status=400)]}).status_code, 200)
        self.assertFalse(MachineStatus.objects.filter(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number).exists())

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_results_out_of_scope_emits_per_check_event(self, post_event):
        # a stored check that flips to N/A emits a per-check status-updated event (OUT_OF_SCOPE + the
        # prior status) before its row is dropped, so probes keyed on the per-check event see it clear
        # — parity with munki's prune path
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        self._results(token, {"results": [self._result(recurring_job, status=300, at="2026-06-22T10:00:00Z")]})
        post_event.reset_mock()  # only the N/A run's events
        with self.captureOnCommitCallbacks(execute=True):
            self._results(token, {"results": [self._result(recurring_job, status=400, at="2026-06-22T11:00:00Z")]})
        cc_events = [c.args[0] for c in post_event.call_args_list
                     if isinstance(c.args[0], TurboMSCPCheckComplianceCheckStatusUpdated)]
        self.assertEqual(len(cc_events), 1)
        self.assertEqual(cc_events[0].payload["status"], "OUT_OF_SCOPE")
        self.assertEqual(cc_events[0].payload["previous_status"], "FAILED")
        self.assertEqual(cc_events[0].payload["mscp_check"], {"pk": str(mscp_check.pk)})
        self.assertFalse(MachineStatus.objects.filter(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number).exists())

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_results_same_job_deduped_latest_status_wins(self, post_event):
        # the agent may report one job several times in a batch; the latest run drives the stored status
        # (a check reaching update_machine_statuses twice would otherwise raise a conflict), but every
        # result is still emitted in the request event
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        # FAILED is the later run but listed first — the status time wins over the batch order
        body = {"results": [
            self._result(recurring_job, status=300, at="2026-06-22T11:00:00Z"),
            self._result(recurring_job, status=0, at="2026-06-22T10:00:00Z"),
        ]}
        with self.captureOnCommitCallbacks(execute=True):
            self.assertEqual(self._results(token, body).status_code, 200)
        machine_status = MachineStatus.objects.get(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number)
        self.assertEqual(machine_status.status, Status.FAILED.value)
        # both results are still emitted — one result event per result
        result_events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], TurboResultEvent)]
        self.assertEqual(len(result_events), 2)

    def test_results_same_job_latest_out_of_scope_not_stored(self):
        # earlier OK, later N/A: the latest run is N/A, so nothing is stored
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        body = {"results": [
            self._result(recurring_job, status=0, at="2026-06-22T10:00:00Z"),
            self._result(recurring_job, status=400, at="2026-06-22T11:00:00Z"),
        ]}
        self.assertEqual(self._results(token, body).status_code, 200)
        self.assertFalse(MachineStatus.objects.filter(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number).exists())

    def test_results_same_job_latest_in_scope_stored(self):
        # earlier N/A, later OK: the latest run is in scope, so OK is stored
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        body = {"results": [
            self._result(recurring_job, status=400, at="2026-06-22T10:00:00Z"),
            self._result(recurring_job, status=0, at="2026-06-22T11:00:00Z"),
        ]}
        self.assertEqual(self._results(token, body).status_code, 200)
        machine_status = MachineStatus.objects.get(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number)
        self.assertEqual(machine_status.status, Status.OK.value)

    def test_results_stale_version_no_status(self):
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        body = {"results": [self._result(recurring_job, version=999, status=300)]}
        self.assertEqual(self._results(token, body).status_code, 200)
        self.assertFalse(MachineStatus.objects.filter(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number).exists())

    def test_results_kind_mismatch_skipped(self):
        # the resolved Job is authoritative for the kind: an entry whose wire kind contradicts it is
        # skipped (logged), the rest of the batch is ingested
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        good = force_mscp_check()
        good_job = force_recurring_job(configuration=configuration, job=good.job)
        bad = self._result(recurring_job, status=300)
        bad["kind"] = "script"
        body = {"results": [bad, self._result(good_job, status=300)]}
        self.assertEqual(self._results(token, body).status_code, 200)
        self.assertFalse(MachineStatus.objects.filter(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number).exists())
        self.assertTrue(MachineStatus.objects.filter(
            compliance_check=good.compliance_check, serial_number=serial_number).exists())

    def test_results_unknown_kind_skipped_and_the_batch_survives(self):
        # the other half of the rolling deploy: the machine takes its config from a new instance, runs
        # the job, and posts the results to an old one. definition_wire_ref() would read .pk on None
        # and 500 the whole batch — every valid entry in it waiting for the refresh to finish.
        configuration, _, serial_number, token = self._enrolled()
        future_job = Job.objects.create(kind="a_kind_from_the_future")
        future = force_one_time_job(configuration=configuration, job=future_job)
        good = force_mscp_check()
        good_job = force_recurring_job(configuration=configuration, job=good.job)
        # the entry names the kind, which the wire accepts as a short string precisely so that a
        # rollout does not drop it (test_results_unnamed_unknown_kind_skipped covers the other shape)
        body = {"results": [self._result(future, status=0), self._result(good_job, status=300)]}
        with self.assertLogs("zentral.contrib.turbo.public_views.results", level="WARNING") as cm:
            response = self._results(token, body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual([s["reason"] for s in response.json()["skipped"]], ["unknown_job_kind"])
        self.assertIn("a_kind_from_the_future", cm.output[0])
        # the rest of the batch was ingested
        self.assertTrue(MachineStatus.objects.filter(
            compliance_check=good.compliance_check, serial_number=serial_number).exists())

    def test_results_unnamed_unknown_kind_skipped(self):
        # kind is optional on the wire, so the same entry without it takes the same path: the
        # resolved job is what decides, never the string the agent sent
        configuration, _, serial_number, token = self._enrolled()
        future_job = Job.objects.create(kind="a_kind_from_the_future")
        future = force_one_time_job(configuration=configuration, job=future_job)
        unnamed = self._result(future, status=0)
        del unnamed["kind"]
        with self.assertLogs("zentral.contrib.turbo.public_views.results", level="WARNING"):
            response = self._results(token, {"results": [unnamed]})
        self.assertEqual([s["reason"] for s in response.json()["skipped"]], ["unknown_job_kind"])

    def test_results_unknown_kind_records_the_run(self):
        # and it consumes the shot, for the same reason kind_mismatch does: the run happened, only the
        # outcome is unusable, and an unrecorded run leaves a one-time gate open forever
        configuration, _, serial_number, token = self._enrolled()
        future_job = Job.objects.create(kind="a_kind_from_the_future")
        future = force_one_time_job(configuration=configuration, job=future_job)
        with self.assertLogs("zentral.contrib.turbo.public_views.results", level="WARNING"):
            self.assertEqual(
                self._results(token, {"results": [self._result(future, status=0)]}).status_code, 200)
        row = OneTimeJobMachine.objects.get(serial_number=serial_number, one_time_job=future)
        self.assertIsNotNone(row.last_result_at)

    def test_results_kind_mismatch_records_the_run(self):
        # a skipped entry whose schedule resolved still records the run: the outcome is discarded, the
        # shot is consumed. Otherwise the one-time gate stays open and config re-serves the job forever.
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        one_time_job = force_one_time_job(configuration=configuration, job=mscp_check.job)
        bad = self._result(one_time_job, status=300)
        bad["kind"] = "script"
        response = self._results(token, {"results": [bad]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["skipped"], [
            {"schedule_pk": str(one_time_job.pk), "at": "2026-06-22T10:00:00+00:00",
             "reason": "kind_mismatch"},
        ])
        # the gate closed
        job_machine = OneTimeJobMachine.objects.get(one_time_job=one_time_job, serial_number=serial_number)
        ran_at = datetime(2026, 6, 22, 10, 0)   # USE_TZ is False, so the ledger keeps naive UTC
        self.assertEqual(job_machine.first_result_at, ran_at)
        self.assertEqual(job_machine.last_result_at, ran_at)
        self.assertEqual(job_machine.last_result_version, mscp_check.job.version)
        # but the outcome was not acted on
        self.assertFalse(MachineStatus.objects.filter(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number).exists())

    def test_results_kind_mismatch_stale_version_does_not_close_the_gate(self):
        # recording the run is not the same as consuming the shot: a stale-version entry records
        # last_result_version and leaves last_result_at unset, skipped or not
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        one_time_job = force_one_time_job(configuration=configuration, job=mscp_check.job)
        bad = self._result(one_time_job, version=999, status=300)
        bad["kind"] = "script"
        self.assertEqual(self._results(token, {"results": [bad]}).status_code, 200)
        job_machine = OneTimeJobMachine.objects.get(one_time_job=one_time_job, serial_number=serial_number)
        self.assertIsNone(job_machine.last_result_at)
        self.assertEqual(job_machine.last_result_version, 999)

    def test_results_unknown_schedule_records_nothing(self):
        # the exception to the rule above: there is no row to record against, and the job is not being
        # served either, so nothing is created
        _, _, serial_number, token = self._enrolled()
        configuration = force_configuration()
        foreign = force_one_time_job(configuration=configuration)
        self.assertEqual(self._results(token, {"results": [self._result(foreign, status=0)]}).status_code, 200)
        self.assertFalse(OneTimeJobMachine.objects.filter(serial_number=serial_number).exists())

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_results_skipped_counts_in_request_event(self, post_event):
        # a set-aside entry produces no TurboResultEvent, so the request event carries the tally
        configuration, _, _, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        bad = self._result(recurring_job, status=300)
        bad["kind"] = "script"
        unknown = self._result(recurring_job, status=0, at="2026-06-22T11:00:00Z")
        unknown["run"]["schedule_pk"] = "1c1cc264-63c7-4aad-b6df-c5be1d5d6adc"
        with self.captureOnCommitCallbacks(execute=True):
            self._results(token, {"results": [bad, unknown, self._result(recurring_job, status=0)]})
        request_events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], TurboRequestEvent)]
        self.assertEqual(len(request_events), 1)
        payload = request_events[0].payload
        self.assertEqual(payload["result_counts"], {"mscp_check": 1})
        self.assertEqual(payload["skipped_counts"], {"kind_mismatch": 1, "unknown_schedule": 1})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_results_no_skipped_counts_when_all_accepted(self, post_event):
        configuration, _, _, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        with self.captureOnCommitCallbacks(execute=True):
            self._results(token, {"results": [self._result(recurring_job, status=0)]})
        request_events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], TurboRequestEvent)]
        self.assertNotIn("skipped_counts", request_events[0].payload)

    def test_results_kind_mismatch_no_spoofed_script_status(self):
        # kind "mscp_check" on a script job must not let the agent write a self-declared status,
        # bypassing the server-side exit-code scoring
        configuration, _, serial_number, token = self._enrolled()
        script = force_script(compliance_check=True)
        recurring_job = force_recurring_job(configuration=configuration, job=script.job)
        spoofed = self._result(recurring_job, status=0)
        spoofed["kind"] = "mscp_check"
        self.assertEqual(self._results(token, {"results": [spoofed]}).status_code, 200)
        self.assertFalse(MachineStatus.objects.filter(
            compliance_check=script.compliance_check, serial_number=serial_number).exists())

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_results_absent_kind_processed_with_job_kind(self, post_event):
        # kind is redundant with the resolved schedule: an entry without it is processed (the agent is
        # expected to send it → warning), and the result event carries the authoritative kind
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        result = self._result(recurring_job, status=300)
        del result["kind"]
        with self.captureOnCommitCallbacks(execute=True), \
                self.assertLogs("zentral.contrib.turbo.public_views.results", level="WARNING") as cm:
            self.assertEqual(self._results(token, {"results": [result]}).status_code, 200)
        self.assertTrue(any("no kind" in msg for msg in cm.output))
        machine_status = MachineStatus.objects.get(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number)
        self.assertEqual(machine_status.status, Status.FAILED.value)
        result_events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], TurboResultEvent)]
        self.assertEqual(len(result_events), 1)
        self.assertEqual(result_events[0].payload["kind"], "mscp_check")

    def test_results_other_configuration_schedule_skipped(self):
        # a scheduling-row pk that belongs to another configuration must not be resolvable by this
        # machine — it is skipped like an unknown pk, so no status is stored and no ledger row minted
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        other_job = force_recurring_job(job=mscp_check.job)  # a different configuration
        body = {"results": [self._result(other_job, status=300)]}
        self.assertEqual(self._results(token, body).status_code, 200)
        self.assertFalse(MachineStatus.objects.filter(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number).exists())
        self.assertEqual(RecurringJobMachine.objects.filter(serial_number=serial_number).count(), 0)

    def test_results_unknown_schedule_skipped(self):
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        result = self._result(recurring_job, status=300)
        recurring_job.delete()   # the schedule the result points at is gone
        self.assertEqual(self._results(token, {"results": [result]}).status_code, 200)
        self.assertFalse(MachineStatus.objects.filter(
            compliance_check=mscp_check.compliance_check, serial_number=serial_number).exists())

    # script — the server evaluates the exit code

    def test_results_script_compliance(self):
        configuration, _, serial_number, token = self._enrolled()
        script = force_script(compliance_check=True)
        recurring_job = force_recurring_job(configuration=configuration, job=script.job)
        body = {"results": [self._result(recurring_job, exit_code=0)]}
        self.assertEqual(self._results(token, body).status_code, 200)
        machine_status = MachineStatus.objects.get(
            compliance_check=script.compliance_check, serial_number=serial_number)
        self.assertEqual(machine_status.status, Status.OK.value)

    def test_results_script_compliance_failed(self):
        configuration, _, serial_number, token = self._enrolled()
        script = force_script(compliance_check=True)
        recurring_job = force_recurring_job(configuration=configuration, job=script.job)
        self._results(token, {"results": [self._result(recurring_job, exit_code=1)]})
        machine_status = MachineStatus.objects.get(
            compliance_check=script.compliance_check, serial_number=serial_number)
        self.assertEqual(machine_status.status, Status.FAILED.value)

    def test_results_script_couldnt_run_is_unknown(self):
        configuration, _, serial_number, token = self._enrolled()
        script = force_script(compliance_check=True)
        recurring_job = force_recurring_job(configuration=configuration, job=script.job)
        self._results(token, {"results": [self._result(recurring_job, exit_code=None)]})
        machine_status = MachineStatus.objects.get(
            compliance_check=script.compliance_check, serial_number=serial_number)
        self.assertEqual(machine_status.status, Status.UNKNOWN.value)

    # script tagging — via the inventory tagging utils

    def test_results_script_tagging_add(self):
        configuration, _, serial_number, token = self._enrolled()
        tag = Tag.objects.create(name=get_random_string(12))
        script = force_script(tag=tag)
        recurring_job = force_recurring_job(configuration=configuration, job=script.job)
        body = {"results": [self._result(recurring_job, exit_code=0)]}
        with self.captureOnCommitCallbacks(execute=True):
            self._results(token, body)
        self.assertTrue(MachineTag.objects.filter(serial_number=serial_number, tag=tag).exists())

    def test_results_script_tagging_remove(self):
        configuration, _, serial_number, token = self._enrolled()
        tag = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number=serial_number, tag=tag)
        script = force_script(tag=tag)
        recurring_job = force_recurring_job(configuration=configuration, job=script.job)
        body = {"results": [self._result(recurring_job, exit_code=1)]}
        with self.captureOnCommitCallbacks(execute=True):
            self._results(token, body)
        self.assertFalse(MachineTag.objects.filter(serial_number=serial_number, tag=tag).exists())

    def test_results_script_tagging_couldnt_run_no_op(self):
        configuration, _, serial_number, token = self._enrolled()
        tag = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number=serial_number, tag=tag)
        script = force_script(tag=tag)
        recurring_job = force_recurring_job(configuration=configuration, job=script.job)
        body = {"results": [self._result(recurring_job, exit_code=None)]}
        with self.captureOnCommitCallbacks(execute=True):
            self._results(token, body)
        self.assertTrue(MachineTag.objects.filter(serial_number=serial_number, tag=tag).exists())

    def test_results_script_tagging_latest_run_wins(self):
        configuration, _, serial_number, token = self._enrolled()
        tag = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number=serial_number, tag=tag)
        script = force_script(tag=tag)
        recurring_job = force_recurring_job(configuration=configuration, job=script.job)
        # a backlog of one script — the later run (remove) wins, regardless of list order
        body = {"results": [self._result(recurring_job, exit_code=1, at="2026-06-22T09:00:00Z"),
                            self._result(recurring_job, exit_code=0, at="2026-06-22T08:00:00Z")]}
        with self.captureOnCommitCallbacks(execute=True):
            self._results(token, body)
        self.assertFalse(MachineTag.objects.filter(serial_number=serial_number, tag=tag).exists())

    # one-time — correlated by run.schedule_pk

    def test_results_one_time(self):
        configuration, _, serial_number, token = self._enrolled()
        one_time_job = force_one_time_job(configuration=configuration)
        body = {"results": [self._result(one_time_job, exit_code=0)]}
        self.assertEqual(self._results(token, body).status_code, 200)
        otjm = OneTimeJobMachine.objects.get(
            serial_number=serial_number, one_time_job=one_time_job)
        self.assertIsNotNone(otjm.last_result_at)

    def test_results_out_of_order_batch_keeps_latest_run_time(self):
        # a drained backlog may arrive out of chronological order; first/last_result_at must reflect the
        # earliest/latest run, not whichever result was listed last
        configuration, _, serial_number, token = self._enrolled()
        recurring_job = force_recurring_job(configuration=configuration)
        body = {"results": [self._result(recurring_job, exit_code=0, at="2026-06-22T11:00:00Z"),
                            self._result(recurring_job, exit_code=0, at="2026-06-22T09:00:00Z"),
                            self._result(recurring_job, exit_code=0, at="2026-06-22T10:00:00Z")]}
        self.assertEqual(self._results(token, body).status_code, 200)
        rjm = RecurringJobMachine.objects.get(
            serial_number=serial_number, recurring_job=recurring_job)
        self.assertEqual(rjm.first_result_at.isoformat(), "2026-06-22T09:00:00")
        self.assertEqual(rjm.last_result_at.isoformat(), "2026-06-22T11:00:00")

    def test_results_last_result_version_follows_latest_run(self):
        # last_result_version records the version of the LATEST run by time, not receipt order: the newer
        # (v1, 11:00) run arrives first, the older (v2, 10:00) run last — last_result_version must be 1
        configuration, _, serial_number, token = self._enrolled()
        recurring_job = force_recurring_job(configuration=configuration)
        recurring_job.job.bump_version()   # job.version → 2
        body = {"results": [self._result(recurring_job, exit_code=0, version=1, at="2026-06-22T11:00:00Z"),
                            self._result(recurring_job, exit_code=0, version=2, at="2026-06-22T10:00:00Z")]}
        self.assertEqual(self._results(token, body).status_code, 200)
        rjm = RecurringJobMachine.objects.get(
            serial_number=serial_number, recurring_job=recurring_job)
        self.assertEqual(rjm.last_result_version, 1)

    # events

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_results_request_and_result_events(self, post_event):
        configuration, enrollment, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        body = {"results": [self._result(recurring_job, status=0, duration=0.3)]}
        with self.captureOnCommitCallbacks(execute=True):
            self._results(token, body)
        # one TurboRequestEvent marks the request itself: its kind, linking the configuration (not the job)
        request_events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], TurboRequestEvent)]
        self.assertEqual(len(request_events), 1)
        request_event = request_events[0]
        self.assertEqual(request_event.payload["request_type"], "results")
        # a summary of how many results were posted per kind — not the results themselves
        self.assertEqual(request_event.payload["result_counts"], {"mscp_check": 1})
        self.assertNotIn("results", request_event.payload)
        request_objects = request_event.metadata.serialize()["objects"]
        self.assertEqual(request_objects["turbo_configuration"], [str(configuration.pk)])
        self.assertNotIn("turbo_job", request_objects)
        # one TurboResultEvent per result: the wire entry (raw run + raw result, no derived verdict),
        # stamped with the result's run time and linking the Job + scheduling row
        result_events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], TurboResultEvent)]
        self.assertEqual(len(result_events), 1)
        result_event = result_events[0]
        self.assertEqual(result_event.payload["kind"], "mscp_check")
        self.assertEqual(result_event.payload["pk"], str(mscp_check.job.pk))
        self.assertEqual(result_event.payload["run"]["duration"], 0.3)
        self.assertEqual(result_event.payload["run"]["mode"], "recurring")
        self.assertEqual(result_event.payload["result"], {"status": 0})
        # the definition block carries the identity + human context (rule_id here); no DB lookup needed
        self.assertEqual(result_event.payload["mscp_check"], {"pk": str(mscp_check.pk), "rule_id": mscp_check.rule_id})
        self.assertEqual(result_event.metadata.created_at.isoformat(), "2026-06-22T10:00:00+00:00")
        result_objects = result_event.metadata.serialize()["objects"]
        self.assertEqual(result_objects["turbo_job"], [str(mscp_check.job.pk)])
        self.assertEqual(result_objects["turbo_recurring_job"], [str(recurring_job.pk)])
        # the definition is linked pk-only under the namespaced key, correlating this event with the
        # check's audit + compliance events
        self.assertEqual(result_objects["turbo_mscp_check"], [str(mscp_check.pk)])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_results_event_script_definition_block(self, post_event):
        # a script result carries the script's name in the payload and links turbo_script pk-only
        configuration, _, _, token = self._enrolled()
        script = force_script()
        recurring_job = force_recurring_job(configuration=configuration, job=script.job)
        with self.captureOnCommitCallbacks(execute=True):
            self._results(token, {"results": [self._result(recurring_job, exit_code=0)]})
        result_event = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], TurboResultEvent)][0]
        self.assertEqual(result_event.payload["script"], {"pk": str(script.pk), "name": script.name})
        self.assertNotIn("mscp_check", result_event.payload)
        self.assertEqual(result_event.metadata.serialize()["objects"]["turbo_script"], [str(script.pk)])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_results_one_result_event_per_result_stamped_with_ran_at(self, post_event):
        # each result becomes its own TurboResultEvent, stamped with that result's run time
        configuration, _, _, token = self._enrolled()
        recurring_job = force_recurring_job(configuration=configuration)
        body = {"results": [self._result(recurring_job, exit_code=0, at="2026-06-22T08:00:00Z"),
                            self._result(recurring_job, exit_code=0, at="2026-06-22T09:00:00Z")]}
        with self.captureOnCommitCallbacks(execute=True):
            self._results(token, body)
        result_events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], TurboResultEvent)]
        self.assertEqual(len(result_events), 2)
        self.assertEqual(
            sorted(e.metadata.created_at.isoformat() for e in result_events),
            ["2026-06-22T08:00:00+00:00", "2026-06-22T09:00:00+00:00"])
        for event in result_events:
            metadata = event.metadata.serialize()
            self.assertEqual(metadata["objects"]["turbo_job"], [str(recurring_job.job.pk)])
            self.assertEqual(metadata["objects"]["turbo_recurring_job"], [str(recurring_job.pk)])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_results_command_result_event(self, post_event):
        # config serves command jobs, so a command result can already arrive. Its outcome rides the
        # open result dict untouched — no verdict, no tagging — and the definition block names the
        # backend so a store consumer can tell one command from another without a lookup.
        configuration, _, serial_number, token = self._enrolled()
        command = force_command(backend=CommandBackend.FILE_EXPORT)
        one_time_job = force_one_time_job(configuration=configuration, job=command.job)
        entry = self._result(one_time_job, exit_code=0)
        entry["result"]["uploads"] = [{"artifact": "manifest", "key": "turbo/uploads/x/manifest.json"}]
        with self.captureOnCommitCallbacks(execute=True):
            response = self._results(token, {"results": [entry]})
        self.assertEqual(response.status_code, 200)
        result_events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], TurboResultEvent)]
        self.assertEqual(len(result_events), 1)
        event = result_events[0]
        self.assertEqual(event.payload["kind"], "file_export")
        self.assertEqual(event.payload["command"],
                         {"pk": str(command.pk), "name": command.name, "backend": "file_export"})
        # the outcome is echoed verbatim, uploads included
        self.assertEqual(event.payload["result"]["uploads"],
                         [{"artifact": "manifest", "key": "turbo/uploads/x/manifest.json"}])
        objects = event.metadata.serialize()["objects"]
        self.assertEqual(objects["turbo_command"], [str(command.pk)])
        self.assertEqual(objects["turbo_one_time_job"], [str(one_time_job.pk)])
        # a command carries no compliance role, so nothing was scored
        self.assertFalse(MachineStatus.objects.filter(serial_number=serial_number).exists())

    def test_results_command_closes_the_gate(self):
        configuration, _, serial_number, token = self._enrolled()
        command = force_command()
        one_time_job = force_one_time_job(configuration=configuration, job=command.job)
        self.assertEqual(self._results(token, {"results": [self._result(one_time_job, exit_code=0)]}).status_code,
                         200)
        job_machine = OneTimeJobMachine.objects.get(one_time_job=one_time_job, serial_number=serial_number)
        self.assertIsNotNone(job_machine.last_result_at)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_results_per_check_mscp_status_event(self, post_event):
        # an mSCP check flipping emits its own status-updated event (in addition to the machine-wide
        # roll-up), mirroring osquery / munki so probes can key on one check
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        body = {"results": [self._result(recurring_job, status=300)]}
        with self.captureOnCommitCallbacks(execute=True):
            self._results(token, body)
        cc_events = [c.args[0] for c in post_event.call_args_list
                     if isinstance(c.args[0], TurboMSCPCheckComplianceCheckStatusUpdated)]
        self.assertEqual(len(cc_events), 1)
        event = cc_events[0]
        self.assertEqual(event.event_type, "turbo_mscp_check_status_updated")
        self.assertIn("turbo_compliance_check", event.tags)
        self.assertEqual(event.payload["status"], "FAILED")
        self.assertEqual(event.payload["pk"], mscp_check.compliance_check.pk)
        # the definition ref sits under the turbo-local payload key; the linked object stays namespaced
        self.assertEqual(event.payload["mscp_check"], {"pk": str(mscp_check.pk)})
        self.assertNotIn("previous_status", event.payload)
        keys = event.get_linked_objects_keys()
        self.assertEqual(keys["compliance_check"], [(mscp_check.compliance_check.pk,)])
        self.assertEqual(keys["turbo_mscp_check"], [(str(mscp_check.pk),)])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_results_per_check_script_status_event(self, post_event):
        # the script check kind emits its own distinct event, linked to the turbo_script
        configuration, _, serial_number, token = self._enrolled()
        script = force_script(compliance_check=True)
        recurring_job = force_recurring_job(configuration=configuration, job=script.job)
        body = {"results": [self._result(recurring_job, exit_code=1)]}
        with self.captureOnCommitCallbacks(execute=True):
            self._results(token, body)
        cc_events = [c.args[0] for c in post_event.call_args_list
                     if isinstance(c.args[0], TurboScriptComplianceCheckStatusUpdated)]
        self.assertEqual(len(cc_events), 1)
        event = cc_events[0]
        self.assertEqual(event.event_type, "turbo_script_check_status_updated")
        self.assertIn("turbo_compliance_check", event.tags)
        self.assertEqual(event.payload["status"], "FAILED")
        self.assertEqual(event.payload["script"], {"pk": str(script.pk)})
        keys = event.get_linked_objects_keys()
        self.assertEqual(keys["compliance_check"], [(script.compliance_check.pk,)])
        self.assertEqual(keys["turbo_script"], [(str(script.pk),)])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_results_per_check_status_event_carries_previous_status(self, post_event):
        # a later run that flips the check reports the prior status in the per-check event
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        self._results(token, {"results": [self._result(recurring_job, status=300, at="2026-06-22T10:00:00Z")]})
        post_event.reset_mock()  # only look at the second run's events
        with self.captureOnCommitCallbacks(execute=True):
            self._results(token, {"results": [self._result(recurring_job, status=0, at="2026-06-22T11:00:00Z")]})
        cc_events = [c.args[0] for c in post_event.call_args_list
                     if isinstance(c.args[0], TurboMSCPCheckComplianceCheckStatusUpdated)]
        self.assertEqual(len(cc_events), 1)
        self.assertEqual(cc_events[0].payload["status"], "OK")
        self.assertEqual(cc_events[0].payload["previous_status"], "FAILED")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_results_unchanged_status_emits_no_per_check_event(self, post_event):
        # a later run reporting the same status (only a newer time) is not a transition: no event fires
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        self._results(token, {"results": [self._result(recurring_job, status=300, at="2026-06-22T10:00:00Z")]})
        post_event.reset_mock()  # only look at the second run's events
        with self.captureOnCommitCallbacks(execute=True):
            self._results(token, {"results": [self._result(recurring_job, status=300, at="2026-06-22T11:00:00Z")]})
        cc_events = [c.args[0] for c in post_event.call_args_list
                     if isinstance(c.args[0], TurboMSCPCheckComplianceCheckStatusUpdated)]
        self.assertEqual(cc_events, [])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_results_machine_compliance_change_event(self, post_event):
        configuration, _, serial_number, token = self._enrolled()
        mscp_check = force_mscp_check()
        recurring_job = force_recurring_job(configuration=configuration, job=mscp_check.job)
        body = {"results": [self._result(recurring_job, status=300)]}
        with self.captureOnCommitCallbacks(execute=True):
            self._results(token, body)
        compliance_events = [c.args[0] for c in post_event.call_args_list
                             if isinstance(c.args[0], MachineComplianceChangeEvent)]
        self.assertEqual(len(compliance_events), 1)
        self.assertEqual(compliance_events[0].payload["status"], "FAILED")
