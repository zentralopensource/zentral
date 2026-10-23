from django.contrib.auth.mixins import LoginRequiredMixin
from ..forms import RecurringJobForm, RecurringJobSearchForm
from ..models import RecurringJob
from ..pbac import (CreateRecurringJobRequest, DeleteRecurringJobRequest, UpdateRecurringJobRequest,
                    ViewRecurringJobRequest)
from .base import (BaseCreateConfigurationScopedJobView, BaseDeleteConfigurationScopedJobView,
                   BaseUpdateConfigurationScopedJobView, ScheduleListView)


class RecurringJobListView(ScheduleListView):
    view_pbac_request_class = ViewRecurringJobRequest
    model = RecurringJob
    search_form_class = RecurringJobSearchForm


class CreateRecurringJobView(LoginRequiredMixin, BaseCreateConfigurationScopedJobView):
    create_pbac_request_class = CreateRecurringJobRequest
    model = RecurringJob
    form_class = RecurringJobForm
    anchor = "recurring-jobs"


class UpdateRecurringJobView(BaseUpdateConfigurationScopedJobView):
    pbac_request_class = UpdateRecurringJobRequest
    model = RecurringJob
    form_class = RecurringJobForm
    anchor = "recurring-jobs"


class DeleteRecurringJobView(BaseDeleteConfigurationScopedJobView):
    pbac_request_class = DeleteRecurringJobRequest
    model = RecurringJob
    anchor = "recurring-jobs"
