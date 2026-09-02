import logging

from django.db.models import Q
from django.http import JsonResponse
from django.utils import timezone

from zentral.contrib.inventory.models import MachineTag
from ..models import Job, OneTimeJob, OneTimeJobMachine, RecurringJob
from .base import BaseEnrolledMachineView

logger = logging.getLogger("zentral.contrib.turbo.public_views.config")


class ConfigView(BaseEnrolledMachineView):
    request_type = "config"

    def _wire(self, job, schedule):
        # a kind this release does not know has no definition to serve — during a rolling deploy an
        # older instance can read a row a newer one wrote. Skip it instead of dereferencing None, or
        # every machine holding that job gets a 500 here until the refresh finishes.
        definition = job.definition
        if definition is None:
            logger.error("Turbo config for %s: unknown job kind %r, skipping job %s",
                         self.serial_number, job.kind, job.pk)
            return None
        return {"kind": job.kind, "pk": str(job.pk), "version": job.version,
                "schedule": schedule, "payload": definition.wire_payload()}

    def get(self, request, *args, **kwargs):
        configuration = self.configuration
        serial_number = self.serial_number
        tag_ids = list(MachineTag.objects.filter(serial_number=serial_number).values_list("tag_id", flat=True))
        jobs = []

        # recurring — every in-scope RecurringJob; null interval falls back to the configuration default
        recurring_jobs = (
            RecurringJob.in_scope(configuration, serial_number, tag_ids)
            .select_related(*Job.definition_relations("job__"))
        )
        for recurring_job in recurring_jobs:
            job = recurring_job.job
            interval = recurring_job.interval or configuration.default_check_interval
            schedule = {"mode": recurring_job.wire_mode, "pk": str(recurring_job.pk), "interval": interval}
            wired = self._wire(job, schedule)
            if wired is not None:
                jobs.append(wired)

        # one-time — in-scope and within the [not_before, not_after] window; keep serving until a result
        # comes back (last_result_at set). The OneTimeJob pk is the wire handle, so nothing is minted here.
        now = timezone.now()
        open_one_time_jobs = list(
            OneTimeJob.in_scope(configuration, serial_number, tag_ids)
            .filter(Q(not_before__isnull=True) | Q(not_before__lte=now))
            .filter(Q(not_after__isnull=True) | Q(not_after__gte=now))
            .select_related(*Job.definition_relations("job__"))
        )
        done = set(
            OneTimeJobMachine.objects
            .filter(serial_number=serial_number, one_time_job__in=open_one_time_jobs,
                    last_result_at__isnull=False)
            .values_list("one_time_job_id", flat=True)
        )
        for one_time_job in open_one_time_jobs:
            if one_time_job.pk in done:
                continue
            job = one_time_job.job
            schedule = {"mode": one_time_job.wire_mode, "pk": str(one_time_job.pk)}
            wired = self._wire(job, schedule)
            if wired is not None:
                jobs.append(wired)

        return JsonResponse({"config_refresh_interval": configuration.config_refresh_interval,
                             "results_batch_size": configuration.results_batch_size,
                             # inventory is not a job in v1 — tell the agent whether/how often to post it
                             "collect_inventory": configuration.collect_inventory,
                             "inventory_interval": configuration.inventory_interval,
                             "jobs": jobs})
