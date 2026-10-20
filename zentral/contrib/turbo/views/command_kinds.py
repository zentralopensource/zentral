from django.contrib.auth.mixins import PermissionRequiredMixin
from django.views.generic import DetailView
from ..forms import FileExportSearchForm, SysdiagnoseSearchForm
from ..models import FileExport, Sysdiagnose
from .base import JobDetailMixin, SearchFormListView


# Read-only in the console for now. An operator defines a sysdiagnose or a file export through
# the API.


class CommandKindDetailMixin(JobDetailMixin):
    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["options"] = self.object.get_backend_kwargs()
        ctx["artifacts"] = self.object.get_backend(load=True).artifacts
        return ctx


class SysdiagnoseListView(SearchFormListView):
    permission_required = "turbo.view_sysdiagnose"
    model = Sysdiagnose
    search_form_class = SysdiagnoseSearchForm


class SysdiagnoseView(PermissionRequiredMixin, CommandKindDetailMixin, DetailView):
    permission_required = "turbo.view_sysdiagnose"

    def get_queryset(self):
        return Sysdiagnose.objects.select_related("job")


class FileExportListView(SearchFormListView):
    permission_required = "turbo.view_fileexport"
    model = FileExport
    search_form_class = FileExportSearchForm


class FileExportView(PermissionRequiredMixin, CommandKindDetailMixin, DetailView):
    permission_required = "turbo.view_fileexport"

    def get_queryset(self):
        return FileExport.objects.select_related("job")
