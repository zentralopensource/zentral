import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView
from zentral.contrib.osquery.forms import FileCategoryForm
from zentral.contrib.osquery.models import FileCategory


logger = logging.getLogger('zentral.contrib.osquery.views.file_categories')


class FileCategoryListView(LoginRequiredMixin, ListView):
    model = FileCategory

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["file_category_count"] = ctx["object_list"].count()
        return ctx


class CreateFileCategoryView(LoginRequiredMixin, CreateView):
    model = FileCategory
    form_class = FileCategoryForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class FileCategoryView(LoginRequiredMixin, DetailView):
    model = FileCategory

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["configurations"] = list(self.object.configuration_set.all().order_by("name", "pk"))
        ctx["configuration_count"] = len(ctx["configurations"])
        return ctx


class UpdateFileCategoryView(LoginRequiredMixin, UpdateView):
    model = FileCategory
    form_class = FileCategoryForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class DeleteFileCategoryView(LoginRequiredMixin, DeleteView):
    model = FileCategory
    success_url = reverse_lazy("osquery:file_categories")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx
