from ..forms import OneTimeJobForm, OneTimeJobSearchForm
from ..models import OneTimeJob, ScheduleMode
from ..pbac import check_schedule_command
from .base import (BaseCreateConfigurationScopedJobView, BaseDeleteConfigurationScopedJobView,
                   BaseUpdateConfigurationScopedJobView, SearchFormListView)


class OneTimeJobListView(SearchFormListView):
    permission_required = "turbo.view_onetimejob"
    model = OneTimeJob
    search_form_class = OneTimeJobSearchForm


class CreateOneTimeJobView(BaseCreateConfigurationScopedJobView):
    permission_required = "turbo.add_onetimejob"
    model = OneTimeJob
    form_class = OneTimeJobForm
    anchor = "one-time-jobs"

    def form_valid(self, form):
        # no machine here: this flow targets a scope expression (tags and serial arrays), so a policy
        # keyed on a machine or an MBU cannot apply. The kind is still policeable, which is why the
        # action is an additional gate rather than a replacement for turbo.add_onetimejob.
        check_schedule_command(self.request, form.cleaned_data["job"], ScheduleMode.ONE_TIME)
        return super().form_valid(form)


class UpdateOneTimeJobView(BaseUpdateConfigurationScopedJobView):
    permission_required = "turbo.change_onetimejob"
    model = OneTimeJob
    form_class = OneTimeJobForm
    anchor = "one-time-jobs"


class DeleteOneTimeJobView(BaseDeleteConfigurationScopedJobView):
    permission_required = "turbo.delete_onetimejob"
    model = OneTimeJob
    anchor = "one-time-jobs"
