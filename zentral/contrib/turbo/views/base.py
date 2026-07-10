from django.contrib.auth.mixins import PermissionRequiredMixin
from django.shortcuts import get_object_or_404
from django.db.models import F
from django.urls import reverse
from zentral.utils.views import (CreateViewWithAudit, DeleteViewWithAudit, UpdateViewWithAudit,
                                 UserPaginationListView)
from ..models import Configuration


class BaseConfigurationScopedJobView:
    # shared by the recurring/one-time create/update/delete views: both are managed on the
    # configuration page and redirect back to it. Subclasses set model, form_class, permission_required
    # and anchor (the configuration-page fragment the success URL jumps to).
    anchor = None

    def get_success_url(self):
        return "{}#{}".format(
            reverse("turbo:configuration", args=(self.kwargs["configuration_pk"],)), self.anchor)


class BaseCreateConfigurationScopedJobView(BaseConfigurationScopedJobView, PermissionRequiredMixin,
                                           CreateViewWithAudit):
    def dispatch(self, request, *args, **kwargs):
        self.configuration = get_object_or_404(Configuration, pk=kwargs["configuration_pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["configuration"] = self.configuration
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.configuration
        return ctx


class BaseConfigurationScopedJobEditView(BaseConfigurationScopedJobView, PermissionRequiredMixin):
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
        ctx["one_time_jobs"] = (
            job.onetimejob_set.select_related("configuration")
            .prefetch_related("tags", "excluded_tags")
            .order_by(F("not_before").desc(nulls_last=True), "-created_at")
        )
        return ctx
