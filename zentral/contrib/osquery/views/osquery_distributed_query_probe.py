import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.generic import FormView, ListView
from zentral.core.probes.models import ProbeSource
from zentral.contrib.osquery.forms import (CreateDistributedQueryProbeForm,
                                           DistributedQueryForm,
                                           DistributedQueryResultFilterForm)
from zentral.core.stores import frontend_store

logger = logging.getLogger('zentral.contrib.osquery.views.osquery_distributed_query_probe')


class CreateDistributedQueryProbeView(LoginRequiredMixin, FormView):
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


class UpdateDistributedQueryProbeQueryView(LoginRequiredMixin, FormView):
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


class DistributedQueryResultSet(object):
    def __init__(self, probe, filter_dict):
        self.probe = probe
        self.store = frontend_store
        self.columns = None
        self._count = None
        self.extra_search_dict = probe.get_extra_event_search_dict()
        if filter_dict:
            self.extra_search_dict.update(filter_dict)

    def count(self):
        if self._count is None:
            self._count = self.store.probe_events_count(self.probe, **self.extra_search_dict)
        return self._count

    def __len__(self):
        return self.count()

    def __getitem__(self, k):
        if isinstance(k, slice):
            start = int(k.start or 0)
            stop = int(k.stop or start + 1)
        else:
            start = k
            stop = k + 1
        results = []
        for event in self.store.probe_events_fetch(self.probe, start, stop, **self.extra_search_dict):
            rows = []
            for result in event.payload.get("result", []):
                if self.columns is None:
                    self.columns = sorted(result.keys())
                rows.append([result.get(attr) for attr in self.columns])
            results.append((event, rows))
        return results


class DistributedQueryResultsTableView(LoginRequiredMixin, ListView):
    template_name = "osquery/distributed_query_results_table.html"
    paginate_by = 10

    def get(self, request, *args, **kwargs):
        probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = probe_source.load()
        filter_form = DistributedQueryResultFilterForm(request.GET)
        if filter_form.is_valid():
            self.filter_form = filter_form
            self.filter_dict = filter_form.get_filter_dict()
        else:
            self.filter_form = DistributedQueryResultFilterForm()
            self.filter_dict = {}
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["probes"] = True
        ctx["probe"] = self.probe
        ctx["filter_form"] = self.filter_form
        # columns
        ctx["columns"] = self.object_list.columns
        # pagination
        page = ctx['page_obj']
        if page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = page.next_page_number()
            ctx['next_url'] = "?{}".format(qd.urlencode())
        if page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = page.previous_page_number()
            ctx['previous_url'] = "?{}".format(qd.urlencode())
        bc = [(reverse('probes:index'), 'Probes'),
              (reverse('probes:probe', args=(self.probe.pk,)), self.probe.name)]
        if page.number > 1:
            qd = self.request.GET.copy()
            qd.pop("page", None)
            reset_link = "?{}".format(qd.urlencode())
        else:
            reset_link = None
        paginator = page.paginator
        if paginator.count:
            count = paginator.count
            pluralize = min(1, count - 1) * 's'
            bc.extend([(reset_link, '{} event{}'.format(count, pluralize)),
                       (None, "page {} of {}".format(page.number, paginator.num_pages))])
        else:
            bc.append((None, "no events"))
        ctx['breadcrumbs'] = bc
        return ctx

    def get_queryset(self):
        return DistributedQueryResultSet(self.probe, self.filter_dict)
