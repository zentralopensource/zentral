from ..forms import OneTimeJobForm, OneTimeJobSearchForm
from ..models import OneTimeJob
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


class UpdateOneTimeJobView(BaseUpdateConfigurationScopedJobView):
    permission_required = "turbo.change_onetimejob"
    model = OneTimeJob
    form_class = OneTimeJobForm
    anchor = "one-time-jobs"


class DeleteOneTimeJobView(BaseDeleteConfigurationScopedJobView):
    permission_required = "turbo.delete_onetimejob"
    model = OneTimeJob
    anchor = "one-time-jobs"
