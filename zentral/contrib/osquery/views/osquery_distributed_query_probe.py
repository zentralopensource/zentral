import logging
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.views.generic.edit import FormView
from zentral.core.probes.models import ProbeSource
from zentral.contrib.osquery.forms import CreateDistributedQueryProbeForm, DistributedQueryForm

logger = logging.getLogger('zentral.contrib.osquery.views.osquery_distributed_query_probe')


class CreateDistributedQueryProbeView(FormView):
    form_class = CreateDistributedQueryProbeForm
    template_name = "core/probes/form.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "Create osquery distributed query probe"
        ctx["probes"] = True
        return ctx

    def form_valid(self, form):
        probe_source = form.save()
        return HttpResponseRedirect(probe_source.get_absolute_url())


class UpdateDistributedQueryProbeQueryView(FormView):
    form_class = DistributedQueryForm
    template_name = "osquery/distributed_query_query_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        return super().dispatch(request, *args, **kwargs)

    def get_initial(self):
        return {'query': self.probe.distributed_query}

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["probes"] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['cancel_url'] = self.probe_source.get_absolute_url("osquery")
        return ctx

    def form_valid(self, form):
        body = form.get_body()

        def func(probe_d):
            probe_d.update(body)
        self.probe_source.update_body(func)
        return super().form_valid(form)

    def get_success_url(self):
        return self.probe_source.get_absolute_url("osquery")
