from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db.models import Count, F, TextField
from django.db.models.functions import Coalesce
from django.urls import reverse_lazy
from django.views.generic import DetailView
from zentral.utils.views import (CreateViewWithAudit, DeleteViewWithAudit, UpdateViewWithAudit,
                                 UserPaginationListView)
from ..forms import ConfigurationForm
from ..models import Configuration


class ConfigurationListView(PermissionRequiredMixin, UserPaginationListView):
    permission_required = "turbo.view_configuration"
    model = Configuration

    def get_queryset(self):
        return super().get_queryset().annotate(Count("enrollment", distinct=True),
                                               Count("enrollment__enrolledmachine")).order_by("name")


class CreateConfigurationView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "turbo.add_configuration"
    model = Configuration
    form_class = ConfigurationForm


class ConfigurationView(PermissionRequiredMixin, DetailView):
    permission_required = "turbo.view_configuration"
    model = Configuration
    one_time_job_preview_count = 10  # the detail page only previews the most recent ones; full list elsewhere

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        enrollments = []
        enrollment_count = 0
        for enrollment in (self.object.enrollment_set
                           .select_related("secret", "distributor_content_type").order_by("pk")):
            enrollment_count += 1
            distributor = None
            distributor_link = False
            dct = enrollment.distributor_content_type
            if dct:
                distributor = enrollment.distributor
                if self.request.user.has_perm(f"{dct.app_label}.view_{dct.model}"):
                    distributor_link = True
            enrollments.append((enrollment, distributor, distributor_link))
        ctx["enrollments"] = enrollments
        ctx["enrollment_count"] = enrollment_count
        recurring_jobs = (
            self.object.recurringjob_set
            .select_related("job__script", "job__mscp_check")
            .prefetch_related("tags", "excluded_tags")
            .annotate(job_name=Coalesce("job__script__name", "job__mscp_check__rule_id",
                                        output_field=TextField()))
            .order_by("job_name", "pk")
        )
        recurring_jobs = list(recurring_jobs)
        ctx["recurring_jobs"] = recurring_jobs
        ctx["recurring_job_count"] = len(recurring_jobs)
        one_time_job_qs = (
            self.object.onetimejob_set
            .select_related("job__script", "job__mscp_check")
            .prefetch_related("tags", "excluded_tags")
            .order_by(F("not_before").desc(nulls_last=True), "-created_at")
        )
        ctx["one_time_job_count"] = one_time_job_qs.count()
        ctx["one_time_jobs"] = one_time_job_qs[:self.one_time_job_preview_count]
        return ctx


class UpdateConfigurationView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "turbo.change_configuration"
    model = Configuration
    form_class = ConfigurationForm


class DeleteConfigurationView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "turbo.delete_configuration"
    model = Configuration
    success_url = reverse_lazy("turbo:configurations")

    def get_queryset(self):
        return Configuration.objects.can_be_deleted()
