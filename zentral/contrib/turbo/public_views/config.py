import logging

from django.db.models import Q
from django.http import JsonResponse
from django.utils import timezone

from zentral.contrib.inventory.models import MetaMachine
from ..models import MachineJobStatus, OneTimeJob, RecurringJob
from .base import BaseEnrolledMachineView

logger = logging.getLogger("zentral.contrib.turbo.public_views.config")


class ConfigView(BaseEnrolledMachineView):
    request_type = "config"

    @staticmethod
    def _wire(job, schedule):
        return {"kind": job.kind, "pk": str(job.pk), "version": job.version,
                "schedule": schedule, "payload": job.definition.wire_payload()}

    def get(self, request, *args, **kwargs):
        configuration = self.configuration
        serial_number = self.serial_number
        tag_ids = [t.pk for t in MetaMachine(serial_number).tags]
        jobs = []

        # recurring — every in-scope RecurringJob; null interval falls back to the configuration default
        recurring_jobs = (
            RecurringJob.in_scope(configuration, serial_number, tag_ids)
            .select_related("job__script", "job__mscp_check")
        )
        for recurring_job in recurring_jobs:
            job = recurring_job.job
            interval = recurring_job.interval or configuration.default_check_interval
            schedule = {"mode": "recurring", "pk": str(recurring_job.pk), "interval": interval}
            jobs.append(self._wire(job, schedule))

        # one-time — in-scope and within the [not_before, not_after] window; keep serving until a result
        # comes back (last_result_at set). The OneTimeJob pk is the wire handle, so nothing is minted here.
        now = timezone.now()
        open_one_time_jobs = list(
            OneTimeJob.in_scope(configuration, serial_number, tag_ids)
            .filter(Q(not_before__isnull=True) | Q(not_before__lte=now))
            .filter(Q(not_after__isnull=True) | Q(not_after__gte=now))
            .select_related("job__script", "job__mscp_check")
        )
        done = set(
            MachineJobStatus.objects
            .filter(serial_number=serial_number, one_time_job__in=open_one_time_jobs,
                    last_result_at__isnull=False)
            .values_list("one_time_job_id", flat=True)
        )
        for one_time_job in open_one_time_jobs:
            if one_time_job.pk in done:
                continue
            job = one_time_job.job
            schedule = {"mode": "one_time", "pk": str(one_time_job.pk)}
            jobs.append(self._wire(job, schedule))

        return JsonResponse({"config_refresh_interval": configuration.config_refresh_interval,
                             "results_batch_size": configuration.results_batch_size,
                             # inventory is not a job in v1 — tell the agent whether/how often to post it
                             "collect_inventory": configuration.collect_inventory,
                             "inventory_interval": configuration.inventory_interval,
                             "jobs": jobs})
