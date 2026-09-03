from zentral.utils.views import PBACViewMixin
from ..forms import OneTimeJobForm, OneTimeJobSearchForm
from ..models import OneTimeJob
from ..pbac import (CreateOneTimeJobRequest, DeleteOneTimeJobRequest, UpdateOneTimeJobRequest,
                    check_create_one_time_job, check_delete_one_time_job,
                    check_update_one_time_job)
from .base import (BaseCreateConfigurationScopedJobView, BaseDeleteConfigurationScopedJobView,
                   BaseUpdateConfigurationScopedJobView, SearchFormListView)


class OneTimeJobListView(SearchFormListView):
    permission_required = "turbo.view_onetimejob"
    model = OneTimeJob
    search_form_class = OneTimeJobSearchForm


class CreateOneTimeJobView(PBACViewMixin, BaseCreateConfigurationScopedJobView):
    pbac_request_class = CreateOneTimeJobRequest

    # no job yet, so this is the preview: may this principal schedule anything in this configuration.
    # form_valid asks again with the job, and that decision is the one that counts.
    def get_pbac_request_kwargs(self, kwargs):
        return {"configuration": self.configuration}
    model = OneTimeJob
    form_class = OneTimeJobForm
    anchor = "one-time-jobs"

    def get_form_kwargs(self):
        # so the picker offers only the kinds a policy would allow here
        return {**super().get_form_kwargs(), "user": self.request.user}

    def form_valid(self, form):
        check_create_one_time_job(self.request, self.configuration, form.cleaned_data["job"])
        return super().form_valid(form)


class UpdateOneTimeJobView(PBACViewMixin, BaseUpdateConfigurationScopedJobView):
    pbac_request_class = UpdateOneTimeJobRequest
    model = OneTimeJob
    form_class = OneTimeJobForm
    anchor = "one-time-jobs"

    # the schedule itself is the resource, and it exists before the form is served: no preview here,
    # the decision is exact from the start
    def get_pbac_request_kwargs(self, kwargs):
        return {"one_time_job": self.get_object()}

    def form_valid(self, form):
        # asked again on submit: dispatch authorized opening the form, this authorizes the change. The
        # job cannot have changed, but the tags, the serial numbers and the window can.
        check_update_one_time_job(self.request, self.object)
        return super().form_valid(form)


class DeleteOneTimeJobView(PBACViewMixin, BaseDeleteConfigurationScopedJobView):
    pbac_request_class = DeleteOneTimeJobRequest
    model = OneTimeJob
    anchor = "one-time-jobs"

    def get_pbac_request_kwargs(self, kwargs):
        return {"one_time_job": self.get_object()}

    def form_valid(self, form):
        # asked again on the POST: dispatch authorized the confirmation page, this authorizes the
        # removal
        check_delete_one_time_job(self.request, self.object)
        return super().form_valid(form)
