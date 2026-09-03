from django.contrib.auth.mixins import PermissionRequiredMixin
from zentral.utils.views import PBACViewMixin
from ..forms import OneTimeJobForm, OneTimeJobSearchForm
from ..models import OneTimeJob
from ..pbac import (DeleteOneTimeJobRequest, UpdateOneTimeJobRequest,
                    check_create_one_time_job, check_delete_one_time_job,
                    check_update_one_time_job)
from .base import (BaseCreateConfigurationScopedJobView, BaseDeleteConfigurationScopedJobView,
                   BaseUpdateConfigurationScopedJobView, SearchFormListView)


class OneTimeJobListView(SearchFormListView):
    permission_required = "turbo.view_onetimejob"
    model = OneTimeJob
    search_form_class = OneTimeJobSearchForm


class CreateOneTimeJobView(PermissionRequiredMixin, BaseCreateConfigurationScopedJobView):
    # createOneTimeJob needs the job, and the form has not picked one yet. A request without it
    # is a preview, which cannot gate a view: it answers "could be permitted", not "is". So the
    # permission opens the form and form_valid decides, like ScheduleMachineOneTimeJobView.
    permission_required = "turbo.view_onetimejob"
    model = OneTimeJob
    form_class = OneTimeJobForm
    anchor = "one-time-jobs"

    def get_form_kwargs(self):
        # the picker then offers only the kinds that a policy permits here
        return {**super().get_form_kwargs(), "user": self.request.user}

    def form_valid(self, form):
        check_create_one_time_job(self.request, self.configuration, form.cleaned_data["job"])
        return super().form_valid(form)


class UpdateOneTimeJobView(PBACViewMixin, BaseUpdateConfigurationScopedJobView):
    pbac_request_class = UpdateOneTimeJobRequest
    model = OneTimeJob
    form_class = OneTimeJobForm
    anchor = "one-time-jobs"

    # The schedule is the resource, and it exists before the form. There is no preview: the
    # first decision is exact.
    def get_pbac_request_kwargs(self, kwargs):
        return {"one_time_job": self.get_object()}

    def form_valid(self, form):
        # Asked again on the submit. dispatch permitted the form, and this permits the change.
        # The job is the same, but the tags, the serial numbers and the window can differ.
        check_update_one_time_job(self.request, self.object)
        return super().form_valid(form)


class DeleteOneTimeJobView(PBACViewMixin, BaseDeleteConfigurationScopedJobView):
    pbac_request_class = DeleteOneTimeJobRequest
    model = OneTimeJob
    anchor = "one-time-jobs"

    def get_pbac_request_kwargs(self, kwargs):
        return {"one_time_job": self.get_object()}

    def form_valid(self, form):
        # Asked again on the POST. dispatch permitted the confirmation page, and this permits
        # the removal.
        check_delete_one_time_job(self.request, self.object)
        return super().form_valid(form)
