import logging
from urllib.parse import urlencode
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core.paginator import InvalidPage, Paginator
from django.db import transaction
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.generic import DetailView, UpdateView
from zentral.core.stores.conf import stores
from zentral.core.stores.views import EventsView, FetchEventsView, EventsStoreRedirectView
from zentral.utils.text import encode_args
from zentral.utils.views import UserPaginationListView, UserPaginationMixin
from .forms import IncidentSearchForm, UpdateIncidentForm, UpdateMachineIncidentForm
from .models import Incident, MachineIncident

logger = logging.getLogger("zentral.core.incidents.views")


class IndexView(PermissionRequiredMixin, UserPaginationListView):
    permission_required = "incidents.view_incident"
    model = Incident
    template_name = "incidents/index.html"

    def get(self, request, *args, **kwargs):
        self.form = IncidentSearchForm(request.GET)
        self.form.is_valid()
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return self.form.get_queryset()

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['form'] = self.form
        page = ctx['page_obj']
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


class IncidentView(PermissionRequiredMixin, UserPaginationMixin, DetailView):
    permission_required = "incidents.view_incident"
    model = Incident

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)

        ctx["objects"] = []
        for title, permissions, objects in self.object.loaded_incident.get_objects_for_display():
            if self.request.user.has_perms(permissions):
                obj_iter = ((obj.get_absolute_url(), obj) for obj in objects)
            else:
                obj_iter = ((None, obj) for obj in objects)
            ctx["objects"].append((title, obj_iter))

        # machine incidents
        try:
            page_number = int(self.request.GET.get("page") or 1)
        except ValueError:
            raise Http404("Invalid page number")
        if page_number != max(1, page_number):
            page_number = 1
        ctx["paginator"] = paginator = Paginator(self.object.machineincident_set.all(), self.get_paginate_by())
        try:
            ctx["page"] = page = paginator.page(page_number)
        except InvalidPage:
            raise Http404("Invalid page number")
        ctx["machine_incidents"] = page.object_list

        # events links
        if self.request.user.has_perms(EventsMixin.permission_required):
            ctx["show_events_link"] = stores.admin_console_store.object_events
            store_links = []
            for store in stores.iter_events_url_store_for_user("object", self.request.user):
                url = "{}?{}".format(
                    reverse("incidents:incident_events_store_redirect", args=(self.object.pk,)),
                    urlencode({"es": store.name,
                               "tr": IncidentEventsView.default_time_range})
                )
                store_links.append((url, store.name))
            ctx["store_links"] = store_links
        return ctx


class UpdateIncidentView(PermissionRequiredMixin, UpdateView):
    permission_required = "incidents.change_incident"
    form_class = UpdateIncidentForm
    model = Incident

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["request"] = self.request
        return kwargs

    def form_valid(self, form):
        response = super().form_valid(form)
        transaction.on_commit(lambda: form.post_event())
        return response


class UpdateMachineIncidentView(PermissionRequiredMixin, UpdateView):
    permission_required = "incidents.change_machineincident"
    form_class = UpdateMachineIncidentForm
    model = MachineIncident

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["request"] = self.request
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["incident"] = ctx["object"].incident
        return ctx

    def form_valid(self, form):
        response = super().form_valid(form)
        transaction.on_commit(lambda: form.post_event())
        return response


# events


class EventsMixin:
    permission_required = ("incidents.view_incident",)
    store_method_scope = "object"

    def get_object(self, **kwargs):
        return get_object_or_404(Incident, pk=kwargs["pk"])

    def get_fetch_kwargs_extra(self):
        return {"key": "incident", "val": encode_args((self.object.pk,))}

    def get_fetch_url(self):
        return reverse("incidents:fetch_incident_events", args=(self.object.pk,))

    def get_redirect_url(self):
        return reverse("incidents:incident_events", args=(self.object.pk,))

    def get_store_redirect_url(self):
        return reverse("incidents:incident_events_store_redirect", args=(self.object.pk,))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["incident"] = self.object
        return ctx


class IncidentEventsView(EventsMixin, EventsView):
    template_name = "incidents/incident_events.html"


class FetchIncidentEventsView(EventsMixin, FetchEventsView):
    pass


class IncidentEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    pass
