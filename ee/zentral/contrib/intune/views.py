import logging
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.core.exceptions import PermissionDenied
from django.urls import reverse_lazy
from django.views.generic import DetailView, ListView, TemplateView
from zentral.utils.views import CreateViewWithAudit, DeleteViewWithAudit, UpdateViewWithAudit
from .forms import TenantForm
from .models import Tenant


logger = logging.getLogger('zentral.contrib.intune.views')


# index


class IndexView(LoginRequiredMixin, TemplateView):
    template_name = "intune/index.html"


# Tenants


class TenantListView(PermissionRequiredMixin, ListView):
    permission_required = "intune.view_tenant"
    model = Tenant


class CreateTenantView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "intune.add_tenant"
    model = Tenant
    form_class = TenantForm


class TenantView(PermissionRequiredMixin, DetailView):
    permission_required = "intune.view_tenant"
    model = Tenant


class UpdateTenantView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "intune.change_tenant"
    model = Tenant
    form_class = TenantForm


class DeleteTenantView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "intune.delete_tenant"
    model = Tenant
    success_url = reverse_lazy("intune:tenants")
