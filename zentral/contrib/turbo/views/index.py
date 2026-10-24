from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.views.generic import TemplateView
from pbac.scoping import visible_row_counts
from ..models import Configuration, OneTimeJob, RecurringJob
from ..pbac import ViewOneTimeJobRequest, ViewRecurringJobRequest


class IndexView(LoginRequiredMixin, TemplateView):
    # Turbo overview: event aggregations + the configurations with their job / enrollment / machine counts
    template_name = "turbo/index.html"

    def get_context_data(self, **kwargs):
        if not self.request.user.has_module_perms("turbo"):
            raise PermissionDenied("Not allowed")
        ctx = super().get_context_data(**kwargs)
        user = self.request.user
        if user.has_perm("turbo.view_configuration"):
            configurations = Configuration.objects.summary()
            # only the schedules that the user can see, as in the lists
            recurring_job_counts = visible_row_counts(user, ViewRecurringJobRequest, RecurringJob.objects.all(),
                                                      "configuration")
            one_time_job_counts = visible_row_counts(user, ViewOneTimeJobRequest, OneTimeJob.objects.all(),
                                                     "configuration")
            for configuration in configurations:
                configuration["recurring_job_count"] = recurring_job_counts.get(configuration["pk"], 0)
                configuration["one_time_job_count"] = one_time_job_counts.get(configuration["pk"], 0)
            ctx["configurations"] = configurations
            ctx["configuration_count"] = len(configurations)
        return ctx
