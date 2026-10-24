from django.contrib.auth.mixins import LoginRequiredMixin
from ..forms import OneTimeJobForm, OneTimeJobSearchForm
from ..models import OneTimeJob
from ..pbac import CreateOneTimeJobRequest, DeleteOneTimeJobRequest, UpdateOneTimeJobRequest, ViewOneTimeJobRequest
from .base import (BaseCreateConfigurationScopedJobView, BaseDeleteConfigurationScopedJobView,
                   BaseUpdateConfigurationScopedJobView, ScheduleListView)


class OneTimeJobListView(ScheduleListView):
    view_pbac_request_class = ViewOneTimeJobRequest
    model = OneTimeJob
    search_form_class = OneTimeJobSearchForm


class CreateOneTimeJobView(LoginRequiredMixin, BaseCreateConfigurationScopedJobView):
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
