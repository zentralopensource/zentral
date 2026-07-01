import json
from unittest.mock import patch
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MachineTag, Tag
from zentral.contrib.turbo.events import (TurboMSCPCheckComplianceCheckStatusUpdated, TurboRequestEvent,
                                          TurboResultEvent, TurboScriptComplianceCheckStatusUpdated)
from zentral.contrib.turbo.models import MachineJobStatus, OneTimeJob
from zentral.core.compliance_checks.events import MachineComplianceChangeEvent
from zentral.core.compliance_checks.models import MachineStatus, Status
from .utils import (TurboPublicTestCase, force_configuration, force_enrolled_machine,
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

    def test_results_malformed_run_at_skipped(self):
        # a single unparseable run.at is skipped (logged), not fatal: the rest of the batch is ingested
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
        self.assertEqual(MachineJobStatus.objects.filter(serial_number=serial_number).count(), 0)

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
        machine_job_status = MachineJobStatus.objects.get(
            serial_number=serial_number, one_time_job=one_time_job)
        self.assertIsNotNone(machine_job_status.last_result_at)

    def test_results_out_of_order_batch_keeps_latest_run_time(self):
        # a drained backlog may arrive out of chronological order; first/last_result_at must reflect the
        # earliest/latest run, not whichever result was listed last
        configuration, _, serial_number, token = self._enrolled()
        recurring_job = force_recurring_job(configuration=configuration)
        body = {"results": [self._result(recurring_job, exit_code=0, at="2026-06-22T11:00:00Z"),
                            self._result(recurring_job, exit_code=0, at="2026-06-22T09:00:00Z"),
                            self._result(recurring_job, exit_code=0, at="2026-06-22T10:00:00Z")]}
        self.assertEqual(self._results(token, body).status_code, 200)
        machine_job_status = MachineJobStatus.objects.get(
            serial_number=serial_number, job=recurring_job.job, one_time_job=None)
        self.assertEqual(machine_job_status.first_result_at.isoformat(), "2026-06-22T09:00:00")
        self.assertEqual(machine_job_status.last_result_at.isoformat(), "2026-06-22T11:00:00")

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
        self.assertNotIn("definition", result_event.payload)
        self.assertEqual(result_event.metadata.created_at.isoformat(), "2026-06-22T10:00:00+00:00")
        result_objects = result_event.metadata.serialize()["objects"]
        self.assertEqual(result_objects["turbo_job"], [str(mscp_check.job.pk)])
        self.assertEqual(result_objects["turbo_recurring_job"], [str(recurring_job.pk)])
        self.assertNotIn("turbo_mscp_check", result_objects)

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
