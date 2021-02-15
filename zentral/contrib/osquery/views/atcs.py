import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView
from zentral.contrib.osquery.forms import ATCForm
from zentral.contrib.osquery.models import AutomaticTableConstruction


logger = logging.getLogger('zentral.contrib.osquery.views.atcs')


class ATCListView(LoginRequiredMixin, ListView):
    model = AutomaticTableConstruction

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["atc_count"] = ctx["object_list"].count()
        return ctx


class CreateATCView(LoginRequiredMixin, CreateView):
    model = AutomaticTableConstruction
    form_class = ATCForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class ATCView(LoginRequiredMixin, DetailView):
    model = AutomaticTableConstruction

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["configurations"] = list(self.object.configuration_set.all().order_by("name", "pk"))
        ctx["configuration_count"] = len(ctx["configurations"])
        return ctx


class UpdateATCView(LoginRequiredMixin, UpdateView):
    model = AutomaticTableConstruction
    form_class = ATCForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class DeleteATCView(LoginRequiredMixin, DeleteView):
    model = AutomaticTableConstruction
    success_url = reverse_lazy("osquery:atcs")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx
