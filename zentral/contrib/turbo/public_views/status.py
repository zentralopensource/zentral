import logging

from django.utils import timezone

from ..models import OneTimeJobMachine, RecurringJobMachine, resolve_machine_schedules
from ..wire import WireStatusSerializer
from .base import BaseEnrolledMachinePostView, WireError

logger = logging.getLogger("zentral.contrib.turbo.public_views.status")


class StatusView(BaseEnrolledMachinePostView):
    """The agent's job-state channel: reconcile the per-machine trackers; the request event reports the held jobs."""

    request_type = "status"

    def do_post(self, data):
        serializer = WireStatusSerializer(data=data)
        if not serializer.is_valid():
            # only the envelope can get here (jobs is not a list) — a malformed jobs value must not be
            # read as "the agent holds nothing", which would mark every ledger row removed
            raise WireError("invalid_jobs")
        for rejected in serializer.rejected:
            logger.warning("Turbo status from %s: rejected job entry %d: %s",
                           self.serial_number, rejected["index"], rejected["errors"])
        accepted, skipped, event_jobs = self._record(self.serial_number, serializer.validated_data["jobs"])
        self.request_event_payload = {"jobs": event_jobs}
        # acknowledge every processed entry; the agent deduces the rejected ones from what is missing
        return {"accepted": accepted, "skipped": skipped}

    def _record(self, serial_number, entries):
        now = timezone.now()
        accepted = []
        skipped = []
        event_jobs = []
        held = {}  # (model, pk) -> tracker row, deduped so each row is written once at the end
        schedules = resolve_machine_schedules(
            self.configuration, serial_number, [entry["schedule"]["pk"] for entry in entries])
        for entry in entries:
            schedule = entry["schedule"]
            schedule_pk = schedule["pk"]
            ack = {"schedule_pk": str(schedule_pk)}
            resolved = schedules.get(schedule_pk)
            if resolved is None:
                logger.warning("Turbo status from %s: unknown schedule %s", serial_number, schedule_pk)
                skipped.append({**ack, "reason": "unknown_schedule"})
                continue
            row, job = resolved
            row.seen_version = entry["version"]
            if isinstance(row, RecurringJobMachine):
                row.seen_interval = schedule["interval"]   # one-time trackers have no interval
            row.last_seen_at = now
            row.removed_at = None   # the agent still holds it
            held[(type(row), row.pk)] = row
            # the event ref IS the validated wire status entry: identity + the held schedule + last_run,
            # plus the definition block (name / rule_id) so the held set links its definitions too
            schedule_ref = {"pk": str(schedule_pk)}
            if schedule.get("mode"):
                schedule_ref["mode"] = schedule["mode"]
            if schedule["interval"] is not None:
                schedule_ref["interval"] = schedule["interval"]
            payload_key, definition_ref = job.definition_wire_ref()
            event_jobs.append({
                "kind": job.kind, "pk": str(job.pk), "version": entry["version"],
                payload_key: definition_ref, "schedule": schedule_ref, "last_run": entry["last_run"],
            })
            accepted.append(ack)
        recurring = [r for r in held.values() if isinstance(r, RecurringJobMachine)]
        one_time = [r for r in held.values() if isinstance(r, OneTimeJobMachine)]
        if recurring:
            RecurringJobMachine.objects.bulk_update(
                recurring, ["seen_version", "seen_interval", "last_seen_at", "removed_at"])
        if one_time:
            OneTimeJobMachine.objects.bulk_update(
                one_time, ["seen_version", "last_seen_at", "removed_at"])
        # the report is the agent's full held set; rows it no longer reports are marked removed (the
        # cleanup command purges them later, sparing live one-time gates)
        RecurringJobMachine.objects.filter(
            serial_number=serial_number, removed_at__isnull=True
        ).exclude(pk__in=[r.pk for r in recurring]).update(removed_at=now)
        OneTimeJobMachine.objects.filter(
            serial_number=serial_number, removed_at__isnull=True
        ).exclude(pk__in=[r.pk for r in one_time]).update(removed_at=now)
        return accepted, skipped, event_jobs
