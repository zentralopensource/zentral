from django.contrib.auth.mixins import PermissionRequiredMixin
from django.shortcuts import get_object_or_404
from django.urls import reverse
from zentral.utils.views import CreateViewWithAudit, DeleteViewWithAudit, UpdateViewWithAudit
from ..forms import OneTimeJobForm, OneTimeJobSearchForm
from ..models import Configuration, OneTimeJob
from .base import SearchFormListView


class OneTimeJobListView(SearchFormListView):
    permission_required = "turbo.view_onetimejob"
    model = OneTimeJob
    search_form_class = OneTimeJobSearchForm


class CreateOneTimeJobView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "turbo.add_onetimejob"
    model = OneTimeJob
    form_class = OneTimeJobForm

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
        return f"{reverse('turbo:configuration', args=(self.configuration.pk,))}#one-time-jobs"


class UpdateOneTimeJobView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "turbo.change_onetimejob"
    model = OneTimeJob
    form_class = OneTimeJobForm

    def get_queryset(self):
        return OneTimeJob.objects.filter(configuration__pk=self.kwargs["configuration_pk"])

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.object.configuration
        return ctx

    def get_success_url(self):
        return f"{reverse('turbo:configuration', args=(self.kwargs['configuration_pk'],))}#one-time-jobs"


class DeleteOneTimeJobView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "turbo.delete_onetimejob"
    model = OneTimeJob

    def get_queryset(self):
        return OneTimeJob.objects.filter(configuration__pk=self.kwargs["configuration_pk"])

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.object.configuration
        return ctx

    def get_success_url(self):
        return f"{reverse('turbo:configuration', args=(self.kwargs['configuration_pk'],))}#one-time-jobs"
