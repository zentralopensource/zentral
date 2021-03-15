import logging
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.urls import reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView
from zentral.contrib.osquery.forms import ATCForm
from zentral.contrib.osquery.models import AutomaticTableConstruction


logger = logging.getLogger('zentral.contrib.osquery.views.atcs')


class ATCListView(PermissionRequiredMixin, ListView):
    permission_required = "osquery.view_automatictableconstruction"
    model = AutomaticTableConstruction

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["atc_count"] = ctx["object_list"].count()
        return ctx


class CreateATCView(PermissionRequiredMixin, CreateView):
    permission_required = "osquery.add_automatictableconstruction"
    model = AutomaticTableConstruction
    form_class = ATCForm


class ATCView(PermissionRequiredMixin, DetailView):
    permission_required = "osquery.view_automatictableconstruction"
    model = AutomaticTableConstruction

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configurations"] = list(self.object.configuration_set.all().order_by("name", "pk"))
        ctx["configuration_count"] = len(ctx["configurations"])
        return ctx


class UpdateATCView(PermissionRequiredMixin, UpdateView):
    permission_required = "osquery.change_automatictableconstruction"
    model = AutomaticTableConstruction
    form_class = ATCForm


class DeleteATCView(PermissionRequiredMixin, DeleteView):
    permission_required = "osquery.delete_automatictableconstruction"
    model = AutomaticTableConstruction
    success_url = reverse_lazy("osquery:atcs")
