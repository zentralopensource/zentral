import logging

from ..events import post_turbo_result_events
from ..models import resolve_machine_schedules
from ..results import ParsedResult, ResultsBatch
from ..wire import WireResultsSerializer
from .base import BaseEnrolledMachinePostView, WireError

logger = logging.getLogger("zentral.contrib.turbo.public_views.results")


class ResultsView(BaseEnrolledMachinePostView):
    request_type = "results"

    def do_post(self, data):
        serializer = WireResultsSerializer(data=data)
        if not serializer.is_valid():
            # only the envelope can get here (results is not a list) — entry problems are tolerated
            raise WireError("invalid_results")
        for rejected in serializer.rejected:
            logger.warning("Turbo results from %s: rejected result entry %d: %s",
                           self.serial_number, rejected["index"], rejected["errors"])
        batch = ResultsBatch(self.serial_number)
        accepted, skipped = self._process(serializer.validated_data["results"], batch)
        batch.commit(self.request)
        self.request_event_payload = {"result_counts": batch.result_counts}
        if skipped:
            # a set-aside entry produces no turbo_result event, so without this a consumed-but-discarded
            # shot leaves nothing in the event stream to find it by
            counts = {}
            for entry in skipped:
                counts[entry["reason"]] = counts.get(entry["reason"], 0) + 1
            self.request_event_payload["skipped_counts"] = counts
        post_turbo_result_events(self.request, self.serial_number, self.enrollment, batch.event_results)
        # acknowledge every processed entry; the agent deduces the rejected ones from what is missing
        return {"accepted": accepted, "skipped": skipped}

    def _process(self, entries, batch):
        # resolve every schedule up front, then feed one ParsedResult per accepted entry to the batch,
        # acknowledging each entry by its (schedule_pk, at) identity
        serial_number = self.serial_number
        accepted = []
        skipped = []
        schedules = resolve_machine_schedules(
            self.configuration, serial_number, [entry["run"]["schedule_pk"] for entry in entries])
        for index, entry in enumerate(entries):
            run = entry["run"]
            schedule_pk = run["schedule_pk"]
            ran_at = run["at"]
            ack = {"schedule_pk": str(schedule_pk), "at": f"{ran_at.isoformat()}+00:00"}
            resolved = schedules.get(schedule_pk)
            if resolved is None:
                logger.warning("Turbo results from %s: unknown schedule %s", serial_number, schedule_pk)
                skipped.append({**ack, "reason": "unknown_schedule"})
                continue
            job_machine, job = resolved
            # the resolved Job is authoritative for the kind: it drives the scoring / tagging branches
            # and is always set in the result event payload. A wire kind contradicting it (confused or
            # hostile agent) skips the entry; an absent one is filled in (with a warning — the agent is
            # expected to send it)
            if job.definition is None:
                # a kind this release does not know: an instance still on the previous release can be
                # handed the results of a job a newer one served. definition_wire_ref() would read
                # .pk on None and 500 the whole batch — every valid entry in it waits for the refresh
                # to finish, with a traceback on each retry.
                logger.warning("Turbo results from %s: unknown kind %r for schedule %s",
                               serial_number, job.kind, schedule_pk)
                batch.record_run(job_machine, job, entry["version"], ran_at)
                skipped.append({**ack, "reason": "unknown_job_kind"})
                continue
            kind = entry["kind"]
            if kind is None:
                logger.warning("Turbo results from %s: no kind, using the schedule's %r",
                               serial_number, job.kind)
            elif kind != job.kind:
                logger.warning("Turbo results from %s: kind %r does not match schedule %s",
                               serial_number, kind, schedule_pk)
                # the outcome is unusable, but the run happened: record it so the shot is consumed. An
                # entry set aside without recording leaves a one-time job's gate open, and config
                # re-serves it on the next refresh — forever, since not_after is nullable.
                batch.record_run(job_machine, job, entry["version"], ran_at)
                skipped.append({**ack, "reason": "kind_mismatch"})
                continue
            kind = job.kind
            outcome = entry["result"]
            batch.add(ParsedResult(
                job=job,
                definition=job.definition,
                job_machine=job_machine,
                kind=kind,
                version=entry["version"],
                outcome=outcome,
                exit_code=outcome.get("exit_code"),
                ran_at=ran_at,
                sort_key=(ran_at, index),
                wire_ref=self._wire_ref(job, kind, entry["version"], run, ran_at, outcome),
            ))
            accepted.append(ack)
        return accepted, skipped

    @staticmethod
    def _wire_ref(job, kind, version, run, ran_at, outcome):
        # the result event payload: the validated wire entry, with the authoritative kind and
        # JSON-native values — the run time as aware ISO-8601 UTC, so EventMetadata parses it back
        # into the event's created_at. The definition block (script / mscp_check) carries the name /
        # rule_id so a store consumer needs no DB lookup, and links the definition (see events).
        run_ref = {"at": f"{ran_at.isoformat()}+00:00", "schedule_pk": str(run["schedule_pk"])}
        if run["duration"] is not None:
            run_ref["duration"] = run["duration"]
        if run.get("mode"):
            run_ref["mode"] = run["mode"]
        payload_key, definition_ref = job.definition_wire_ref()
        return {"kind": kind, "pk": str(job.pk), "version": version,
                payload_key: definition_ref, "run": run_ref, "result": outcome}
