import logging

from django.core.files.storage import storages
from django.utils import timezone

from ..events import post_turbo_result_events
from ..models import JobUpload, UploadErrorReason, UploadStatus, resolve_machine_schedules
from ..results import ParsedResult, ResultsBatch
from ..uploads import verify_upload
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
            # before the wire ref is built, not after: the verification verdict rides the echoed
            # upload entry into the event, and enriching `outcome` in place afterwards would only
            # work by aliasing a dict two callers hold
            uploads_ref = self._close_uploads(schedule_pk, run.get("id"), outcome)
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
                wire_ref=self._wire_ref(job, kind, entry["version"], run, ran_at, outcome,
                                        uploads_ref),
            ))
            accepted.append(ack)
        return accepted, skipped

    def _close_uploads(self, schedule_pk, run_id, outcome):
        """Move this run's upload rows out of `pending`, on the agent's word, then ask the storage.

        The gate closes here and nowhere else, and it closes on the agent's report alone. Whether the
        storage agrees is a *second* axis: it is recorded next to the status, never instead of it, and
        it cannot reopen a shot the report consumed. Tolerant, like the rest of ingest — a row that
        cannot be matched is logged and skipped, never a reason to fail the batch, because the run did
        happen and the outcome is already recorded.

        Returns the echoed entries with the verdict added, for the result event, or None when there
        was nothing to close.
        """
        uploads = outcome.get("uploads")
        if not uploads or not isinstance(uploads, list):
            return None
        if run_id is None:
            # nothing to match on: the rows are keyed by run, and two runs of one schedule are
            # otherwise indistinguishable
            logger.warning("Turbo results from %s: uploads without a run id on schedule %s",
                           self.serial_number, schedule_pk)
            return None
        rows = {row.artifact: row for row in JobUpload.objects.filter(
            schedule_pk=schedule_pk, serial_number=self.serial_number, run_id=run_id)}
        storage = storages["default"]
        uploads_ref = []
        for reported in uploads:
            uploads_ref.append(reported)
            if not isinstance(reported, dict):
                continue
            artifact = reported.get("artifact")
            row = rows.get(artifact)
            if row is None:
                # an artifact the agent never minted for, or a name it invented
                logger.warning("Turbo results from %s: no upload row for %r on run %s",
                               self.serial_number, artifact, run_id)
                continue
            if row.status != UploadStatus.PENDING:
                continue
            error = reported.get("error")
            if isinstance(error, dict):
                reason = error.get("reason")
                row.status = UploadStatus.FAILED
                row.error_reason = (reason if reason in UploadErrorReason.values else None)
            else:
                # the key is NOT taken from the wire — it is compared to the one we minted. An echo
                # that does not match is the agent talking about a different object than the one we
                # signed, so the row is not closed as uploaded.
                if reported.get("key") != row.key:
                    logger.warning("Turbo results from %s: echoed key does not match for %r on run %s",
                                   self.serial_number, artifact, run_id)
                    row.status = UploadStatus.FAILED
                    row.error_reason = None
                else:
                    row.status = UploadStatus.UPLOADED
                    row.truncated = bool(reported.get("truncated"))
            row.completed_at = timezone.now()
            if row.status == UploadStatus.UPLOADED:
                verification = verify_upload(row, reported, storage)
                if verification is not None:
                    row.verification = verification
                    row.verified_at = timezone.now()
                    # the verdict, not a boolean: `missing` and `mismatch` both answer "no" and
                    # mean different things, and a consumer that has to tell them apart cannot go
                    # to the database from an event
                    uploads_ref[-1] = {**reported, "verification": verification}
            row.save()
        return uploads_ref

    @staticmethod
    def _wire_ref(job, kind, version, run, ran_at, outcome, uploads_ref=None):
        # the result event payload: the validated wire entry, with the authoritative kind and
        # JSON-native values — the run time as aware ISO-8601 UTC, so EventMetadata parses it back
        # into the event's created_at. The definition block (script / mscp_check) carries the name /
        # rule_id so a store consumer needs no DB lookup, and links the definition (see events).
        run_ref = {"at": f"{ran_at.isoformat()}+00:00", "schedule_pk": str(run["schedule_pk"])}
        if run["duration"] is not None:
            run_ref["duration"] = run["duration"]
        if run.get("mode"):
            run_ref["mode"] = run["mode"]
        if run.get("id"):
            # what an upload row is keyed on, so a consumer of the event can find the artifact it
            # describes
            run_ref["id"] = str(run["id"])
        result_ref = outcome
        if uploads_ref is not None:
            # a copy: `outcome` is also the ParsedResult's, and the verdict belongs to the event
            result_ref = {**outcome, "uploads": uploads_ref}
        payload_key, definition_ref = job.definition_wire_ref()
        return {"kind": kind, "pk": str(job.pk), "version": version,
                payload_key: definition_ref, "run": run_ref, "result": result_ref}
