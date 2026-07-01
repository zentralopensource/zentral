from ..forms import RecurringJobForm, RecurringJobSearchForm
from ..models import RecurringJob
from .base import (BaseCreateConfigurationScopedJobView, BaseDeleteConfigurationScopedJobView,
                   BaseUpdateConfigurationScopedJobView, SearchFormListView)


class RecurringJobListView(SearchFormListView):
    permission_required = "turbo.view_recurringjob"
    model = RecurringJob
    search_form_class = RecurringJobSearchForm


class CreateRecurringJobView(BaseCreateConfigurationScopedJobView):
    permission_required = "turbo.add_recurringjob"
    model = RecurringJob
    form_class = RecurringJobForm
    anchor = "recurring-jobs"


class UpdateRecurringJobView(BaseUpdateConfigurationScopedJobView):
    permission_required = "turbo.change_recurringjob"
    model = RecurringJob
    form_class = RecurringJobForm
    anchor = "recurring-jobs"


class DeleteRecurringJobView(BaseDeleteConfigurationScopedJobView):
    permission_required = "turbo.delete_recurringjob"
    model = RecurringJob
    anchor = "recurring-jobs"
