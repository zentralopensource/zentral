from django.contrib.auth.mixins import PermissionRequiredMixin
from django.urls import reverse_lazy
from django.views.generic import DetailView
from zentral.utils.views import CreateViewWithAudit, DeleteViewWithAudit, UpdateViewWithAudit
from ..forms import ScriptForm, ScriptSearchForm
from ..models import Script
from .base import JobDetailMixin, SearchFormListView


class ScriptListView(SearchFormListView):
    permission_required = "turbo.view_script"
    model = Script
    search_form_class = ScriptSearchForm


class CreateScriptView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "turbo.add_script"
    model = Script
    form_class = ScriptForm


class ScriptView(PermissionRequiredMixin, JobDetailMixin, DetailView):
    permission_required = "turbo.view_script"

    def get_queryset(self):
        return Script.objects.select_related("job", "compliance_check", "tag")


class UpdateScriptView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "turbo.change_script"
    model = Script
    form_class = ScriptForm


class DeleteScriptView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "turbo.delete_script"
    model = Script
    success_url = reverse_lazy("turbo:scripts")

    def get_queryset(self):
        return Script.objects.can_be_deleted()
