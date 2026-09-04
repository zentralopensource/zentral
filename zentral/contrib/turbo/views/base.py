from functools import cached_property

from django.contrib.auth.mixins import PermissionRequiredMixin
from django.shortcuts import get_object_or_404
from django.db.models import F
from django.urls import reverse
from zentral.utils.views import (CreateViewWithAudit, DeleteViewWithAudit, UpdateViewWithAudit,
                                 UserPaginationListView)
from ..models import Configuration
from ..pbac import authorize_one_time_job_rows


class BaseConfigurationScopedJobView:
    # shared by the recurring/one-time create/update/delete views: both are managed on the
    # configuration page and redirect back to it. Subclasses set model, form_class, anchor (the
    # configuration-page fragment the success URL jumps to) and their own authorization mixin —
    # PermissionRequiredMixin for the recurring views, PBACViewMixin for the one-time ones.
    anchor = None

    @cached_property
    def configuration(self):
        # lazy, so that nothing is read from the database before the authorization mixin has run: an
        # anonymous request for an unknown pk gets the login redirect, not a 404. PBACViewMixin calls
        # get_pbac_request_kwargs() after its is_authenticated check, so that is the first reader.
        return get_object_or_404(Configuration, pk=self.kwargs["configuration_pk"])

    def get_success_url(self):
        return "{}#{}".format(
            reverse("turbo:configuration", args=(self.kwargs["configuration_pk"],)), self.anchor)


class BaseCreateConfigurationScopedJobView(BaseConfigurationScopedJobView, CreateViewWithAudit):
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["configuration"] = self.configuration
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.configuration
        return ctx


class BaseConfigurationScopedJobEditView(BaseConfigurationScopedJobView):
    # update + delete: scope the queryset to the configuration in the URL, expose it to the template
    def get_queryset(self):
        return self.model.objects.filter(configuration__pk=self.kwargs["configuration_pk"])

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
    # shared by ScriptView / MSCPCheckView: the scheduled and one-time jobs that run this definition
    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        job = self.object.job
        ctx["recurring_jobs"] = (
            job.recurringjob_set.select_related("configuration")
            .prefetch_related("tags", "excluded_tags")
            .order_by("configuration__name", "pk")
        )
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
