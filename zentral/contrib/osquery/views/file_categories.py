import logging
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.urls import reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView
from zentral.contrib.osquery.forms import FileCategoryForm
from zentral.contrib.osquery.models import FileCategory


logger = logging.getLogger('zentral.contrib.osquery.views.file_categories')


class FileCategoryListView(PermissionRequiredMixin, ListView):
    permission_required = "osquery.view_filecategory"
    model = FileCategory

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["file_category_count"] = ctx["object_list"].count()
        return ctx


class CreateFileCategoryView(PermissionRequiredMixin, CreateView):
    permission_required = "osquery.add_filecategory"
    model = FileCategory
    form_class = FileCategoryForm


class FileCategoryView(PermissionRequiredMixin, DetailView):
    permission_required = "osquery.view_filecategory"
    model = FileCategory

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configurations"] = list(self.object.configuration_set.all().order_by("name", "pk"))
        ctx["configuration_count"] = len(ctx["configurations"])
        return ctx


class UpdateFileCategoryView(PermissionRequiredMixin, UpdateView):
    permission_required = "osquery.change_filecategory"
    model = FileCategory
    form_class = FileCategoryForm


class DeleteFileCategoryView(PermissionRequiredMixin, DeleteView):
    permission_required = "osquery.delete_filecategory"
    model = FileCategory
    success_url = reverse_lazy("osquery:file_categories")
