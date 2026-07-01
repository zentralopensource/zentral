import logging

from django.utils import timezone

from ..models import MachineJobStatus
from .base import BaseEnrolledMachinePostView

logger = logging.getLogger("zentral.contrib.turbo.public_views.status")


class StatusView(BaseEnrolledMachinePostView):
    """The agent's job-state channel: reconcile the per-machine ledger; the request event reports the held jobs."""

    request_type = "status"

    def do_post(self, data):
        serial_number = self.serial_number
        self.request_event_payload = {"jobs": self._record(serial_number, data.get("jobs") or [])}
        return {}

    def _record(self, serial_number, jobs):
        now = timezone.now()
        event_jobs = []
        held = {}  # pk -> MachineJobStatus, deduped so the ledger is written once at the end
        schedules = MachineJobStatus.objects.resolve_schedules(
            self.configuration, serial_number, [(entry.get("schedule") or {}).get("pk") for entry in jobs])
        for entry in jobs:
            schedule = entry.get("schedule") or {}
            resolved = schedules.get(schedule.get("pk"))
            if resolved is None:
                logger.warning("Turbo status from %s: unknown schedule %s", serial_number, schedule.get("pk"))
                continue
            machine_job_status, job = resolved
            machine_job_status.seen_version = entry.get("version")
            machine_job_status.seen_interval = schedule.get("interval")
            machine_job_status.last_seen_at = now
            machine_job_status.removed_at = None   # the agent still holds it
            held[machine_job_status.pk] = machine_job_status
            # the event ref IS the wire status entry: identity + the held schedule + last_run
            event_jobs.append({
                "kind": job.kind, "pk": str(job.pk), "version": entry.get("version"),
                "schedule": schedule, "last_run": entry.get("last_run"),
            })
        if held:
            MachineJobStatus.objects.bulk_update(
                held.values(), ["seen_version", "seen_interval", "last_seen_at", "removed_at"])
        # the report is the agent's full held set; rows it no longer reports are marked removed (the
        # cleanup command purges them later, sparing live one-time gates)
        (MachineJobStatus.objects
         .filter(serial_number=serial_number, removed_at__isnull=True)
         .exclude(pk__in=held)
         .update(removed_at=now))
        return event_jobs
