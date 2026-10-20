from django.contrib.auth.mixins import PermissionRequiredMixin
from ..forms import OneTimeJobForm, OneTimeJobSearchForm
from ..models import OneTimeJob
from ..pbac import CreateOneTimeJobRequest, DeleteOneTimeJobRequest, UpdateOneTimeJobRequest
from .base import (BaseCreateConfigurationScopedJobView, BaseDeleteConfigurationScopedJobView,
                   BaseUpdateConfigurationScopedJobView, SearchFormListView)


class OneTimeJobListView(SearchFormListView):
    permission_required = "turbo.view_onetimejob"
    model = OneTimeJob
    search_form_class = OneTimeJobSearchForm


class CreateOneTimeJobView(PermissionRequiredMixin, BaseCreateConfigurationScopedJobView):
    permission_required = "turbo.view_onetimejob"
    create_pbac_request_class = CreateOneTimeJobRequest
    model = OneTimeJob
    form_class = OneTimeJobForm
    anchor = "one-time-jobs"


class UpdateOneTimeJobView(BaseUpdateConfigurationScopedJobView):
    pbac_request_class = UpdateOneTimeJobRequest
    model = OneTimeJob
    form_class = OneTimeJobForm
    anchor = "one-time-jobs"


class DeleteOneTimeJobView(BaseDeleteConfigurationScopedJobView):
    pbac_request_class = DeleteOneTimeJobRequest
    model = OneTimeJob
    anchor = "one-time-jobs"
