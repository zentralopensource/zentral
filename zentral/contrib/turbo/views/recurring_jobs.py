from django.contrib.auth.mixins import PermissionRequiredMixin
from ..forms import RecurringJobForm, RecurringJobSearchForm
from ..models import RecurringJob
from ..pbac import CreateRecurringJobRequest, DeleteRecurringJobRequest, UpdateRecurringJobRequest
from .base import (BaseCreateConfigurationScopedJobView, BaseDeleteConfigurationScopedJobView,
                   BaseUpdateConfigurationScopedJobView, SearchFormListView)


class RecurringJobListView(SearchFormListView):
    permission_required = "turbo.view_recurringjob"
    model = RecurringJob
    search_form_class = RecurringJobSearchForm


class CreateRecurringJobView(PermissionRequiredMixin, BaseCreateConfigurationScopedJobView):
    permission_required = "turbo.view_recurringjob"
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
