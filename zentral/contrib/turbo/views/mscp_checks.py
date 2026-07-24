from django.contrib.auth.mixins import PermissionRequiredMixin
from django.urls import reverse_lazy
from django.views.generic import DetailView
from zentral.utils.views import CreateViewWithAudit, DeleteViewWithAudit, UpdateViewWithAudit
from ..forms import MSCPCheckForm, MSCPCheckSearchForm
from ..models import MSCPCheck
from .base import JobDetailMixin, SearchFormListView


class MSCPCheckListView(SearchFormListView):
    permission_required = "turbo.view_mscpcheck"
    model = MSCPCheck
    search_form_class = MSCPCheckSearchForm


class CreateMSCPCheckView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "turbo.add_mscpcheck"
    model = MSCPCheck
    form_class = MSCPCheckForm


class MSCPCheckView(PermissionRequiredMixin, JobDetailMixin, DetailView):
    permission_required = "turbo.view_mscpcheck"

    def get_queryset(self):
        return MSCPCheck.objects.select_related("job", "compliance_check")


class UpdateMSCPCheckView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "turbo.change_mscpcheck"
    model = MSCPCheck
    form_class = MSCPCheckForm


class DeleteMSCPCheckView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "turbo.delete_mscpcheck"
    model = MSCPCheck
    success_url = reverse_lazy("turbo:mscp_checks")

    def get_queryset(self):
        return MSCPCheck.objects.can_be_deleted()
