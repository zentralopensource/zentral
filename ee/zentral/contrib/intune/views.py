import logging
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect
from django.urls import reverse_lazy
from django.views.generic import DetailView, ListView, TemplateView
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from .forms import TenantForm
from .models import Tenant


logger = logging.getLogger('zentral.contrib.intune.views')


# index


class IndexView(LoginRequiredMixin, TemplateView):
    template_name = "intune/index.html"

    def get_context_data(self, **kwargs):
        if not self.request.user.has_module_perms("intune"):
            raise PermissionDenied("Not allowed")
        ctx = super().get_context_data(**kwargs)
        tenant_qs = Tenant.objects.all()
        ctx["tenants"] = tenant_qs
        ctx["tenant_count"] = tenant_qs.count()
        return ctx


# Tenants


class TenantListView(PermissionRequiredMixin, ListView):
    permission_required = "intune.view_tenant"
    model = Tenant


class CreateTenantView(PermissionRequiredMixin, CreateView):
    permission_required = "intune.add_tenant"
    model = Tenant
    form_class = TenantForm

    def form_valid(self, form):
        response = super().form_valid(form)
        return response


class TenantView(PermissionRequiredMixin, DetailView):
    permission_required = "intune.view_tenant"
    model = Tenant

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        return ctx


class UpdateTenantView(PermissionRequiredMixin, UpdateView):
    permission_required = "intune.change_tenant"
    model = Tenant
    form_class = TenantForm

    def form_valid(self, form):
        response = super().form_valid(form)
        return response


class DeleteTenantView(PermissionRequiredMixin, DeleteView):
    permission_required = "intune.delete_tenant"
    model = Tenant
    success_url = reverse_lazy("intune:tenants")

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        success_url = self.get_success_url()
        self.object.delete()
        return HttpResponseRedirect(success_url)
