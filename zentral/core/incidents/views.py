import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse
from django.views.generic import DetailView, ListView
from .forms import IncidentSearchForm
from .models import Incident

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
        return ctx
