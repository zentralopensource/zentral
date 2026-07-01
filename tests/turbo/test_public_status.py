import json
from unittest.mock import patch
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from zentral.contrib.turbo.events import TurboRequestEvent
from zentral.contrib.turbo.models import MachineJobStatus, OneTimeJob
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

    def test_status_records_recurring(self):
        configuration, _, serial_number, token = self._enrolled()
        recurring_job = force_recurring_job(configuration=configuration, interval=3600)
        body = {"jobs": [self._entry(recurring_job,
                                     last_run={"at": "2026-06-22T09:00:00Z", "duration": 0.5})]}
        self.assertEqual(self._status(token, body).status_code, 200)
        machine_job_status = MachineJobStatus.objects.get(
            serial_number=serial_number, job=recurring_job.job, one_time_job=None)
        self.assertEqual(machine_job_status.seen_version, recurring_job.job.version)
        self.assertEqual(machine_job_status.seen_interval, 3600)
        self.assertIsNotNone(machine_job_status.last_seen_at)

    def test_status_records_one_time(self):
        configuration, _, serial_number, token = self._enrolled()
        one_time_job = force_one_time_job(configuration=configuration)
        body = {"jobs": [self._entry(one_time_job, last_run=None)]}
        self.assertEqual(self._status(token, body).status_code, 200)
        machine_job_status = MachineJobStatus.objects.get(
            serial_number=serial_number, one_time_job=one_time_job)
        self.assertEqual(machine_job_status.seen_version, one_time_job.job.version)
        self.assertIsNotNone(machine_job_status.last_seen_at)

    def test_status_marks_absent_jobs_removed(self):
        configuration, _, serial_number, token = self._enrolled()
        held = force_recurring_job(configuration=configuration)
        dropped = force_recurring_job(configuration=configuration)
        self._status(token, {"jobs": [self._entry(held), self._entry(dropped)]})
        # a later report no longer holding `dropped` marks it removed, leaves `held` alone
        self._status(token, {"jobs": [self._entry(held)]})
        self.assertIsNone(
            MachineJobStatus.objects.get(serial_number=serial_number, job=held.job).removed_at)
        self.assertIsNotNone(
            MachineJobStatus.objects.get(serial_number=serial_number, job=dropped.job).removed_at)

    def test_status_reappearing_job_clears_removed(self):
        configuration, _, serial_number, token = self._enrolled()
        recurring_job = force_recurring_job(configuration=configuration)
        self._status(token, {"jobs": [self._entry(recurring_job)]})
        self._status(token, {"jobs": []})
        machine_job_status = MachineJobStatus.objects.get(serial_number=serial_number, job=recurring_job.job)
        self.assertIsNotNone(machine_job_status.removed_at)
        self._status(token, {"jobs": [self._entry(recurring_job)]})
        machine_job_status.refresh_from_db()
        self.assertIsNone(machine_job_status.removed_at)

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
        self.assertEqual(MachineJobStatus.objects.filter(serial_number=serial_number).count(), 0)

    def test_status_unknown_schedule_skipped(self):
        configuration, _, serial_number, token = self._enrolled()
        recurring_job = force_recurring_job(configuration=configuration)
        entry = self._entry(recurring_job)
        recurring_job.delete()
        self.assertEqual(self._status(token, {"jobs": [entry]}).status_code, 200)
        self.assertEqual(MachineJobStatus.objects.filter(serial_number=serial_number).count(), 0)

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
        # last_run rides in the event only — it is never stored on MachineJobStatus
        self.assertEqual(event.payload["jobs"][0]["last_run"], last_run)
        self.assertNotIn("definition", event.payload["jobs"][0])
        metadata = event.metadata.serialize()
        # link the Job (reaches the definition) and the scheduling row
        self.assertEqual(metadata["objects"]["turbo_job"], [str(recurring_job.job.pk)])
        self.assertEqual(metadata["objects"]["turbo_recurring_job"], [str(recurring_job.pk)])
        self.assertEqual(metadata["objects"]["turbo_configuration"], [str(configuration.pk)])
