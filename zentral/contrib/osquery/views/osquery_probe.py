import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponseRedirect
from django.views.generic.edit import FormView
from zentral.core.probes.views import AddProbeItemView, UpdateProbeItemView, DeleteProbeItemView
from zentral.contrib.osquery.forms import CreateProbeForm, DiscoveryForm, QueryForm

logger = logging.getLogger('zentral.contrib.osquery.views.osquery_probe')


class CreateProbeView(LoginRequiredMixin, FormView):
    form_class = CreateProbeForm
    template_name = "core/probes/form.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "Create osquery probe"
        ctx["probes"] = True
        return ctx

    def form_valid(self, form):
        probe_source = form.save()
        return HttpResponseRedirect(probe_source.get_absolute_url())


# discovery


class AddProbeDiscoveryView(AddProbeItemView):
    form_class = DiscoveryForm
    probe_item_attribute = "discovery"
    template_name = "osquery/discovery_form.html"

    success_anchor = "osquery"


class UpdateProbeDiscoveryView(UpdateProbeItemView):
    form_class = DiscoveryForm
    probe_item_attribute = "discovery"
    item_pk_kwarg = "discovery_id"
    template_name = "osquery/discovery_form.html"
    success_anchor = "osquery"


class DeleteProbeDiscoveryView(DeleteProbeItemView):
    probe_item_attribute = "discovery"
    item_pk_kwarg = "discovery_id"
    template_name = "osquery/delete_discovery.html"
    success_anchor = "osquery"

# queries


class AddProbeQueryView(AddProbeItemView):
    form_class = QueryForm
    probe_item_attribute = "queries"
    template_name = "osquery/query_form.html"
    success_anchor = "osquery"


class UpdateProbeQueryView(UpdateProbeItemView):
    form_class = QueryForm
    probe_item_attribute = "queries"
    item_pk_kwarg = "query_id"
    template_name = "osquery/query_form.html"
    success_anchor = "osquery"


class DeleteProbeQueryView(DeleteProbeItemView):
    probe_item_attribute = "queries"
    permission = "can_delete_queries"
    item_pk_kwarg = "query_id"
    template_name = "osquery/delete_query.html"
    success_anchor = "osquery"
