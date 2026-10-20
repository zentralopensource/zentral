from functools import cached_property

from django.contrib.auth.mixins import PermissionRequiredMixin
from django.shortcuts import get_object_or_404
from django.db.models import F
from django.urls import reverse
from zentral.utils.views import (CreateViewWithAudit, DeleteViewWithAudit, PBACViewMixin, UpdateViewWithAudit,
                                 UserPaginationListView)
from ..models import Configuration
from pbac.utils import check_request
from ..pbac import authorize_one_time_job_rows, authorize_recurring_job_rows


class BaseConfigurationScopedJobView:
    # shared by the recurring/one-time create/update/delete views: both are managed on the
    # configuration page and redirect back to it. A subclass sets model, form_class, anchor (the
    # fragment of the success URL) and its PBAC request class.
    anchor = None

    @cached_property
    def configuration(self):
        # Lazy, so that no code reads the database before the authorization mixin runs. An
        # anonymous request for an unknown pk then gets the login redirect, not a 404.
        # PBACViewMixin calls get_pbac_request_kwargs() after its is_authenticated check, and
        # that is the first read.
        return get_object_or_404(Configuration, pk=self.kwargs["configuration_pk"])

    def get_success_url(self):
        return "{}#{}".format(
            reverse("turbo:configuration", args=(self.kwargs["configuration_pk"],)), self.anchor)


class BaseCreateConfigurationScopedJobView(BaseConfigurationScopedJobView, CreateViewWithAudit):
    # The create action needs the job, and the form has not picked one yet. A request without it
    # is a preview: it answers "could be permitted", not "is". So a view permission opens the form,
    # dispatch refuses it when no kind can be permitted here, and form_valid decides.
    create_pbac_request_class = None

    def dispatch(self, request, *args, **kwargs):
        check_request(request, self.create_pbac_request_class(request.user, self.configuration))
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["configuration"] = self.configuration
        # the picker then offers only the kinds that a policy permits here
        kwargs["user"] = self.request.user
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.configuration
        return ctx

    def form_valid(self, form):
        pbac_request = self.create_pbac_request_class(self.request.user, self.configuration,
                                                      form.cleaned_data["job"])
        check_request(self.request, pbac_request)
        return super().form_valid(form)


class BaseConfigurationScopedJobEditView(PBACViewMixin, BaseConfigurationScopedJobView):
    # update + delete: scope the queryset to the configuration in the URL, expose it to the template.
    # The schedule is the resource, and it exists before the form, so the decision in dispatch is
    # exact, on the GET and on the POST.
    def get_queryset(self):
        return self.model.objects.filter(configuration__pk=self.kwargs["configuration_pk"])

    def get_pbac_request_kwargs(self, kwargs):
        return {"schedule": self.get_object()}

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.object.configuration
        return ctx


class BaseUpdateConfigurationScopedJobView(BaseConfigurationScopedJobEditView, UpdateViewWithAudit):
    pass


class BaseDeleteConfigurationScopedJobView(BaseConfigurationScopedJobEditView, DeleteViewWithAudit):
    pass


class SearchFormListView(PermissionRequiredMixin, UserPaginationListView):
    # a list view driven by a search form exposing get_queryset(); subclasses set search_form_class
    search_form_class = None

    def get(self, request, *args, **kwargs):
        self.form = self.search_form_class(request.GET)
        self.form.is_valid()
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return self.form.get_queryset()

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["form"] = self.form
        page = ctx["page_obj"]
        if page.number > 1:
            qd = self.request.GET.copy()
            qd.pop("page", None)
            ctx["reset_link"] = f"?{qd.urlencode()}"
        return ctx


class JobDetailMixin:
    # the recurring and one-time jobs that run this definition
    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        job = self.object.job
        recurring_jobs = authorize_recurring_job_rows(
            self.request.user,
            job.recurringjob_set.select_related("configuration")
            .prefetch_related("tags", "excluded_tags")
            .order_by("configuration__name", "pk")
        )
        ctx["recurring_jobs"] = recurring_jobs
        ctx["can_edit_recurring_job"] = any(rj.can_update or rj.can_delete
                                            for rj in recurring_jobs)
        one_time_jobs = authorize_one_time_job_rows(
            self.request.user,
            job.onetimejob_set.select_related("configuration")
            .prefetch_related("tags", "excluded_tags")
            .order_by(F("not_before").desc(nulls_last=True), "-created_at")
        )
        ctx["one_time_jobs"] = one_time_jobs
        ctx["can_edit_one_time_job"] = any(otj.can_update or otj.can_delete
                                           for otj in one_time_jobs)
        return ctx
