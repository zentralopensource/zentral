from django.contrib.auth.mixins import PermissionRequiredMixin
from django.shortcuts import get_object_or_404
from django.urls import reverse
from zentral.utils.views import CreateViewWithAudit, DeleteViewWithAudit, UpdateViewWithAudit
from ..forms import RecurringJobForm, RecurringJobSearchForm
from ..models import Configuration, RecurringJob
from .base import SearchFormListView


class RecurringJobListView(SearchFormListView):
    permission_required = "turbo.view_recurringjob"
    model = RecurringJob
    search_form_class = RecurringJobSearchForm


class CreateRecurringJobView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "turbo.add_recurringjob"
    model = RecurringJob
    form_class = RecurringJobForm

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

    def get_success_url(self):
        return f"{reverse('turbo:configuration', args=(self.configuration.pk,))}#recurring-jobs"


class UpdateRecurringJobView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "turbo.change_recurringjob"
    model = RecurringJob
    form_class = RecurringJobForm

    def get_queryset(self):
        return RecurringJob.objects.filter(configuration__pk=self.kwargs["configuration_pk"])

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.object.configuration
        return ctx

    def get_success_url(self):
        return f"{reverse('turbo:configuration', args=(self.kwargs['configuration_pk'],))}#recurring-jobs"


class DeleteRecurringJobView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "turbo.delete_recurringjob"
    model = RecurringJob

    def get_queryset(self):
        return RecurringJob.objects.filter(configuration__pk=self.kwargs["configuration_pk"])

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.object.configuration
        return ctx

    def get_success_url(self):
        return f"{reverse('turbo:configuration', args=(self.kwargs['configuration_pk'],))}#recurring-jobs"
