import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.generic import DetailView, ListView, UpdateView
from zentral.core.stores import frontend_store, stores
from zentral.utils.prometheus import BasePrometheusMetricsView
from .forms import IncidentSearchForm, UpdateIncidentForm, UpdateMachineIncidentForm
from .models import Incident, MachineIncident
from .utils import get_prometheus_incidents_metrics

logger = logging.getLogger("zentral.core.incidents.views")


class IndexView(LoginRequiredMixin, ListView):
    model = Incident
    paginate_by = 50
    template_name = "incidents/index.html"

    def get(self, request, *args, **kwargs):
        self.form = IncidentSearchForm(request.GET)
        self.form.is_valid()
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return self.form.get_queryset()

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['incidents'] = True
        ctx['form'] = self.form
        page = ctx['page_obj']
        if page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = page.next_page_number()
            ctx['next_url'] = "?{}".format(qd.urlencode())
        if page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = page.previous_page_number()
            ctx['previous_url'] = "?{}".format(qd.urlencode())
        bc = []
        if page.number > 1:
            qd = self.request.GET.copy()
            qd.pop("page", None)
            reset_link = "?{}".format(qd.urlencode())
        else:
            reset_link = None
        if not self.form.is_initial():
            bc.append((reverse("incidents:index"), "Incidents"))
            bc.append((reset_link, "Search"))
        else:
            bc.append((reset_link, "Incidents"))
        bc.append((None, "page {} of {}".format(page.number, page.paginator.num_pages)))
        ctx["breadcrumbs"] = bc
        return ctx


class IncidentView(LoginRequiredMixin, DetailView):
    model = Incident

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["incidents"] = True
        ctx["machine_incidents"] = ctx["object"].machineincident_set.all()
        ctx["machine_incidents_count"] = ctx["machine_incidents"].count()
        ctx["store_links"] = []
        for store in stores:
            url = store.get_incident_vis_url(ctx["object"])
            if url:
                ctx["store_links"].append((store.name, url))
        ctx["store_links"].sort()
        return ctx


class UpdateIncidentView(LoginRequiredMixin, UpdateView):
    form_class = UpdateIncidentForm
    model = Incident

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["incidents"] = True
        return ctx


class IncidentEventSet(object):
    def __init__(self, incident):
        self.incident = incident
        self.store = frontend_store
        self._count = None

    def count(self):
        if self._count is None:
            self._count = self.store.incident_events_count(self.incident)
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
        return self.store.incident_events_fetch(self.incident, start, stop - start)


class IncidentEventsView(LoginRequiredMixin, ListView):
    template_name = "incidents/incident_events.html"
    paginate_by = 10

    def get(self, request, *args, **kwargs):
        self.incident = get_object_or_404(Incident, pk=kwargs["pk"])
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["incidents"] = True
        ctx["incident"] = self.incident
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
        bc = [(reverse('incidents:index'), 'Incidents'),
              (reverse('incidents:incident', args=(self.incident.pk,)), self.incident.name)]
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
        return IncidentEventSet(self.incident)


class UpdateMachineIncidentView(LoginRequiredMixin, UpdateView):
    form_class = UpdateMachineIncidentForm
    model = MachineIncident

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["incidents"] = True
        ctx["incident"] = ctx["object"].incident
        return ctx


class PrometheusMetricsView(BasePrometheusMetricsView):
    def get_registry(self):
        return get_prometheus_incidents_metrics()
