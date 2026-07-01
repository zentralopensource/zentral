import logging
from datetime import datetime

from zentral.utils.time import parse_naive_datetime
from ..events import post_turbo_result_events
from ..models import MachineJobStatus
from ..results import ParsedResult, ResultsBatch
from .base import BaseEnrolledMachinePostView

logger = logging.getLogger("zentral.contrib.turbo.public_views.results")


class ResultsView(BaseEnrolledMachinePostView):
    request_type = "results"

    def do_post(self, data):
        batch = ResultsBatch(self.serial_number)
        for parsed in self._parse(data.get("results") or []):
            batch.add(parsed)
        batch.commit(self.request)
        self.request_event_payload = {"result_counts": batch.result_counts}
        post_turbo_result_events(self.request, self.serial_number, self.enrollment, batch.event_results)
        return {}

    def _parse(self, results):
        # resolve every schedule up front, then yield one ParsedResult per result, skipping (and logging)
        # results whose scheduling row is gone
        serial_number = self.serial_number
        schedules = MachineJobStatus.objects.resolve_schedules(
            self.configuration, serial_number, [(r.get("run") or {}).get("schedule_pk") for r in results])
        for index, result in enumerate(results):
            run = result.get("run") or {}
            resolved = schedules.get(run.get("schedule_pk"))
            if resolved is None:
                logger.warning("Turbo results from %s: unknown schedule %s", serial_number, run.get("schedule_pk"))
                continue
            machine_job_status, job = resolved
            kind = result.get("kind")
            version = result.get("version")
            outcome = result.get("result") or {}
            # a single unparseable run.at must not 500 the whole batch (the agent would just retry the
            # same poisoned payload forever) — log it and skip only that result
            at = run.get("at")
            ran_at = None
            if at:
                try:
                    ran_at = parse_naive_datetime(at)
                except (ValueError, OverflowError, TypeError):
                    logger.error("Turbo results from %s: unparseable run.at %r", serial_number, at)
                    continue
            yield ParsedResult(
                job=job,
                definition=job.definition,
                machine_job_status=machine_job_status,
                kind=kind,
                version=version,
                outcome=outcome,
                exit_code=outcome.get("exit_code"),
                ran_at=ran_at,
                sort_key=(ran_at or datetime.min, index),
                # the event ref IS the wire result entry: raw run (incl. mode) + raw result
                wire_ref={"kind": kind, "pk": str(job.pk), "version": version, "run": run, "result": outcome},
            )
