import json
from unittest.mock import patch
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.turbo.events import TurboRequestEvent
from zentral.contrib.turbo.models import Job, OneTimeJob, OneTimeJobMachine, RecurringJobMachine
from .utils import (TurboPublicTestCase, force_configuration, force_enrolled_machine,
                    force_one_time_job, force_recurring_job)


class TurboStatusPublicTestCase(TurboPublicTestCase):
    def _status(self, token, body):
        return self.client.post(
            reverse("turbo_public:status"),
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
    def _entry(schedule, version=None, last_run=None):
        job = schedule.job
        if isinstance(schedule, OneTimeJob):
            sched = {"mode": "one_time", "pk": str(schedule.pk)}
        else:
            sched = {"mode": "recurring", "pk": str(schedule.pk)}
            if schedule.interval is not None:
                sched["interval"] = schedule.interval
        return {"kind": job.kind, "pk": str(job.pk),
                "version": job.version if version is None else version,
                "schedule": sched, "last_run": last_run}

    def test_status_unauthenticated(self):
        self.assertEqual(self.client.post(reverse("turbo_public:status")).status_code, 401)

    def test_status_invalid_json(self):
        _, _, _, token = self._enrolled()
        response = self.client.post(reverse("turbo_public:status"), data="not json",
                                    content_type="application/json",
                                    HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_json"})

    def test_status_non_object_body(self):
        _, _, _, token = self._enrolled()
        response = self.client.post(reverse("turbo_public:status"), data="[]",
                                    content_type="application/json",
                                    HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_json"})

    def test_status_non_list_jobs_rejected_without_marking_removed(self):
        # a malformed jobs value must not be read as "the agent holds nothing" — the ledger stays put
        configuration, _, serial_number, token = self._enrolled()
        recurring_job = force_recurring_job(configuration=configuration)
        self.assertEqual(self._status(token, {"jobs": [self._entry(recurring_job)]}).status_code, 200)
        response = self._status(token, {"jobs": "garbage"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_jobs"})
        rjm = RecurringJobMachine.objects.get(
            serial_number=serial_number, recurring_job=recurring_job)
        self.assertIsNone(rjm.removed_at)

    def test_status_malformed_entries_rejected(self):
        configuration, _, serial_number, token = self._enrolled()
        recurring_job = force_recurring_job(configuration=configuration)
        body = {"jobs": [42, "garbage", {"schedule": "nope"}, self._entry(recurring_job)]}
        response = self._status(token, body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(),
                         {"accepted": [{"schedule_pk": str(recurring_job.pk)}], "skipped": []})
        rjm = RecurringJobMachine.objects.get(
            serial_number=serial_number, recurring_job=recurring_job)
        self.assertIsNotNone(rjm.last_seen_at)

    def test_status_invalid_entry_rejected(self):
        # an entry that does not validate against the wire schema (garbage version / interval) is
        # rejected whole: no ledger row is minted for it, it is absent from the acknowledgment, and
        # the request still succeeds
        configuration, _, serial_number, token = self._enrolled()
        recurring_job = force_recurring_job(configuration=configuration, interval=3600)
        garbage_types = self._entry(recurring_job, version="three")
        garbage_types["schedule"]["interval"] = "soon"
        out_of_range_version = self._entry(recurring_job, version=-1)
        out_of_range_interval = self._entry(recurring_job)
        out_of_range_interval["schedule"]["interval"] = 2 ** 40
        for bad_entry in (garbage_types, out_of_range_version, out_of_range_interval):
            response = self._status(token, {"jobs": [bad_entry]})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {"accepted": [], "skipped": []})
            self.assertEqual(RecurringJobMachine.objects.filter(serial_number=serial_number).count(), 0)

    def test_status_response_acknowledges_entries(self):
        # the response always enumerates the accepted and skipped entries, keyed by schedule_pk;
        # the agent deduces the rejected ones from what is missing
        configuration, _, serial_number, token = self._enrolled()
        recurring_job = force_recurring_job(configuration=configuration)
        unknown = self._entry(recurring_job)
        unknown["schedule"] = {"mode": "recurring", "pk": "1c1cc264-63c7-4aad-b6df-c5be1d5d6adc"}
        body = {"jobs": [self._entry(recurring_job), unknown, "garbage"]}
        response = self._status(token, body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "accepted": [{"schedule_pk": str(recurring_job.pk)}],
            "skipped": [{"schedule_pk": "1c1cc264-63c7-4aad-b6df-c5be1d5d6adc",
                         "reason": "unknown_schedule"}],
        })

    def test_status_records_recurring(self):
        configuration, _, serial_number, token = self._enrolled()
        recurring_job = force_recurring_job(configuration=configuration, interval=3600)
        body = {"jobs": [self._entry(recurring_job,
                                     last_run={"at": "2026-06-22T09:00:00Z", "duration": 0.5})]}
        self.assertEqual(self._status(token, body).status_code, 200)
        rjm = RecurringJobMachine.objects.get(
            serial_number=serial_number, recurring_job=recurring_job)
        self.assertEqual(rjm.seen_version, recurring_job.job.version)
        self.assertEqual(rjm.seen_interval, 3600)
        self.assertIsNotNone(rjm.last_seen_at)

    def test_status_records_one_time(self):
        configuration, _, serial_number, token = self._enrolled()
        one_time_job = force_one_time_job(configuration=configuration)
        body = {"jobs": [self._entry(one_time_job, last_run=None)]}
        self.assertEqual(self._status(token, body).status_code, 200)
        otjm = OneTimeJobMachine.objects.get(
            serial_number=serial_number, one_time_job=one_time_job)
        self.assertEqual(otjm.seen_version, one_time_job.job.version)
        self.assertIsNotNone(otjm.last_seen_at)

    def test_status_marks_absent_jobs_removed(self):
        configuration, _, serial_number, token = self._enrolled()
        held = force_recurring_job(configuration=configuration)
        dropped = force_recurring_job(configuration=configuration)
        dropped_one_time = force_one_time_job(configuration=configuration)
        self._status(token, {"jobs": [self._entry(held), self._entry(dropped),
                                      self._entry(dropped_one_time)]})
        # a later report no longer holding the dropped jobs marks them removed in both tables, leaving
        # `held` alone
        self._status(token, {"jobs": [self._entry(held)]})
        self.assertIsNone(
            RecurringJobMachine.objects.get(serial_number=serial_number, recurring_job=held).removed_at)
        self.assertIsNotNone(
            RecurringJobMachine.objects.get(serial_number=serial_number, recurring_job=dropped).removed_at)
        self.assertIsNotNone(
            OneTimeJobMachine.objects.get(
                serial_number=serial_number, one_time_job=dropped_one_time).removed_at)

    def test_status_reappearing_job_clears_removed(self):
        configuration, _, serial_number, token = self._enrolled()
        recurring_job = force_recurring_job(configuration=configuration)
        self._status(token, {"jobs": [self._entry(recurring_job)]})
        self._status(token, {"jobs": []})
        rjm = RecurringJobMachine.objects.get(serial_number=serial_number, recurring_job=recurring_job)
        self.assertIsNotNone(rjm.removed_at)
        self._status(token, {"jobs": [self._entry(recurring_job)]})
        rjm.refresh_from_db()
        self.assertIsNone(rjm.removed_at)

    def test_status_query_count_constant_regardless_of_batch_size(self):
        # the batched ledger update must cost the same number of queries no matter how many jobs
        # the agent reports — a regression to per-entry resolution would make the count grow with N
        configuration = force_configuration()
        recurring_jobs = [force_recurring_job(configuration=configuration) for _ in range(5)]

        def post_query_count(n):
            # a fresh machine each call, so every post is a first-contact creating its own ledger rows
            _, _, token = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
            body = {"jobs": [self._entry(j) for j in recurring_jobs[:n]]}
            with CaptureQueriesContext(connection) as ctx:
                self.assertEqual(self._status(token, body).status_code, 200)
            return len(ctx.captured_queries)

        post_query_count(1)  # warm process-level caches (content types, …) before measuring
        self.assertEqual(post_query_count(1), post_query_count(5))

    def test_status_other_configuration_schedule_skipped(self):
        # a scheduling row from another configuration must not be resolvable by this machine
        configuration, _, serial_number, token = self._enrolled()
        other_job = force_recurring_job()  # a different configuration
        self.assertEqual(self._status(token, {"jobs": [self._entry(other_job)]}).status_code, 200)
        self.assertEqual(RecurringJobMachine.objects.filter(serial_number=serial_number).count(), 0)

    def test_status_unknown_schedule_skipped(self):
        configuration, _, serial_number, token = self._enrolled()
        recurring_job = force_recurring_job(configuration=configuration)
        entry = self._entry(recurring_job)
        recurring_job.delete()
        self.assertEqual(self._status(token, {"jobs": [entry]}).status_code, 200)
        self.assertEqual(RecurringJobMachine.objects.filter(serial_number=serial_number).count(), 0)

    def test_status_unknown_kind_holds_the_row_and_skips_the_entry(self):
        # the third face of the rolling deploy: the machine holds a job a newer instance served and
        # posts its status to an older one. definition_wire_ref() reads .pk on None, so the whole
        # batch 500s. The tracker still has to be written, or the next sweep marks a job the agent is
        # holding as removed. The entry names the kind, which the wire accepts as a short string so
        # that a rollout does not drop it.
        configuration, _, serial_number, token = self._enrolled()
        future_job = Job.objects.create(kind="a_kind_from_the_future")
        future = force_one_time_job(configuration=configuration, job=future_job)
        entry = self._entry(future)
        with self.assertLogs("zentral.contrib.turbo.public_views.status", level="WARNING") as cm:
            response = self._status(token, {"jobs": [entry]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual([s["reason"] for s in response.json()["skipped"]], ["unknown_job_kind"])
        self.assertIn("a_kind_from_the_future", cm.output[0])
        row = OneTimeJobMachine.objects.get(serial_number=serial_number, one_time_job=future)
        self.assertIsNone(row.removed_at)
        self.assertEqual(row.seen_version, future.job.version)

    def test_request_event_heartbeat_timeout_from_configuration(self):
        # the heartbeat timeout follows the machine's config_refresh_interval (2×), not a static value
        configuration = force_configuration()
        configuration.config_refresh_interval = 1800
        configuration.save()
        _, serial_number, _ = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        self.assertEqual(TurboRequestEvent.get_machine_heartbeat_timeout(serial_number), 3600)

    def test_request_event_heartbeat_timeout_unknown_serial(self):
        self.assertIsNone(TurboRequestEvent.get_machine_heartbeat_timeout(get_random_string(12)))

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_status_event(self, post_event):
        configuration, enrollment, serial_number, token = self._enrolled()
        recurring_job = force_recurring_job(configuration=configuration, interval=3600)
        last_run = {"at": "2026-06-22T09:00:00Z", "duration": 0.5}
        body = {"jobs": [self._entry(recurring_job, last_run=last_run)]}
        with self.captureOnCommitCallbacks(execute=True):
            self._status(token, body)
        events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], TurboRequestEvent)]
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.event_type, "turbo_request")
        self.assertEqual(event.payload["request_type"], "status")
        self.assertEqual(len(event.payload["jobs"]), 1)
        self.assertEqual(event.payload["jobs"][0]["pk"], str(recurring_job.job.pk))
        # last_run rides in the event only — it is never stored on the per-machine tracker
        self.assertEqual(event.payload["jobs"][0]["last_run"], last_run)
        # the held job carries its definition block (name here — the default job is a script)
        script = recurring_job.job.script
        self.assertEqual(event.payload["jobs"][0]["script"], {"pk": str(script.pk), "name": script.name})
        metadata = event.metadata.serialize()
        # link the Job, the scheduling row and the definition
        self.assertEqual(metadata["objects"]["turbo_job"], [str(recurring_job.job.pk)])
        self.assertEqual(metadata["objects"]["turbo_recurring_job"], [str(recurring_job.pk)])
        self.assertEqual(metadata["objects"]["turbo_script"], [str(script.pk)])
        self.assertEqual(metadata["objects"]["turbo_configuration"], [str(configuration.pk)])
