import logging
from django.core.urlresolvers import reverse_lazy
from django.views.generic import ListView, DetailView
from django.views.generic.edit import CreateView, DeleteView, UpdateView
from . import BaseProbe
from .models import ProbeSource

logger = logging.getLogger("zentral.core.probes.views")


class IndexView(ListView):
    model = ProbeSource
    template_name = "core/probes/index.html"

    def get_context_data(self, **kwargs):
        ctx = super(IndexView, self).get_context_data(**kwargs)
        ctx['probes'] = True
        return ctx


class CreateProbeView(CreateView):
    model = ProbeSource
    fields = ['name', 'status', 'description', 'body']
    template_name = "core/probes/form.html"

    def get_context_data(self, **kwargs):
        ctx = super(CreateProbeView, self).get_context_data(**kwargs)
        ctx['probes'] = True
        return ctx


class ProbeView(DetailView):
    model = ProbeSource

    def get_context_data(self, **kwargs):
        ctx = super(ProbeView, self).get_context_data(**kwargs)
        ctx['probes'] = True
        self.probe = self.object.load()
        ctx['probe'] = self.probe
        ctx['probe_links'] = self.probe.get_probe_links()
        ctx.update(self.probe.get_extra_context())
        return ctx

    def get_template_names(self):
        template_names = ["core/probes/probe.html"]
        if not self.probe.__class__ == BaseProbe:
            probe_module_name = self.probe.__class__.__module__
            if probe_module_name.endswith(".probes"):
                contrib_module_name = probe_module_name.split(".")[-2]
                template_names.insert(0, "{}/probe.html".format(contrib_module_name))
            else:
                logger.error("unknown probe module name %s", probe_module_name)
        return template_names


class UpdateProbeView(UpdateView):
    model = ProbeSource
    fields = ['name', 'status', 'description', 'body']
    template_name = "core/probes/form.html"

    def get_context_data(self, **kwargs):
        ctx = super(UpdateProbeView, self).get_context_data(**kwargs)
        ctx['probes'] = True
        return ctx


class DeleteProbeView(DeleteView):
    model = ProbeSource
    template_name = "core/probes/delete.html"
    success_url = reverse_lazy('probes:index')

    def get_context_data(self, **kwargs):
        ctx = super(DeleteProbeView, self).get_context_data(**kwargs)
        ctx['inventory'] = True
        return ctx
