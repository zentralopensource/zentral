import logging
from urllib.parse import urlencode

from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db.models import Exists, OuterRef
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.views.generic import (
    DeleteView,
    DetailView,
    FormView,
    TemplateView,
    UpdateView,
)

from zentral.core.stores.conf import stores
from zentral.core.stores.views import (
    EventsStoreRedirectView,
    EventsView,
    FetchEventsView,
)
from zentral.utils.views import UserPaginationListView

from .forms import (
    CloneProbeForm,
    CreateProbeForm,
    InventoryFilterForm,
    MetadataFilterForm,
    PayloadFilterFormSet,
    ProbeSearchForm,
    UpdateProbeForm,
)
from .models import Action, ProbeSource
from .probe import Probe

logger = logging.getLogger("zentral.core.probes.views")


class ActionDetail(PermissionRequiredMixin, DetailView):
    permission_required = "probes.view_action"
    model = Action

    def get_queryset(self):
        return super().get_queryset().prefetch_related("probesource_set")


class ActionList(PermissionRequiredMixin, UserPaginationListView):
    permission_required = "probes.view_action"
    model = Action

    def get_queryset(self):

        return (
            super()
            .get_queryset()
            .annotate(
                has_probesource=Exists(
                    ProbeSource.objects.filter(actions=OuterRef("pk"))
                )
            )
            .order_by("name")
        )


class IndexView(PermissionRequiredMixin, UserPaginationListView):
    permission_required = "probes.view_probesource"
    model = ProbeSource
    template_name = "probes/index.html"

    def get(self, request, *args, **kwargs):
        qd = self.request.GET.copy()
        self.form = ProbeSearchForm(qd)
        self.form.is_valid()
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return self.form.get_queryset()

    def get_context_data(self, **kwargs):
        ctx = super(IndexView, self).get_context_data(**kwargs)
        ctx['form'] = self.form
        page = ctx['page_obj']
        bc = []
        if page.number > 1:
            qd = self.request.GET.copy()
            qd.pop("page", None)
            reset_link = "?{}".format(qd.urlencode())
        else:
            reset_link = None
        if self.form.has_changed():
            bc.append((reverse("probes:index"), "Probes"))
            bc.append((reset_link, "Search"))
        else:
            bc.append((reset_link, "Probes"))
        bc.append((None, "page {} of {}".format(page.number, page.paginator.num_pages)))
        ctx["breadcrumbs"] = bc
        return ctx


class CreateProbeView(PermissionRequiredMixin, FormView):
    permission_required = "probes.add_probesource"
    form_class = CreateProbeForm
    template_name = "probes/form.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['title'] = "Create event probe"
        return ctx

    def form_valid(self, form):
        probe_source = form.save()
        return HttpResponseRedirect(probe_source.get_absolute_url())


class ProbeView(PermissionRequiredMixin, DetailView):
    permission_required = "probes.view_probesource"
    model = ProbeSource

    def get_context_data(self, **kwargs):
        ctx = super(ProbeView, self).get_context_data(**kwargs)
        ctx['probe'] = self.probe = Probe(self.object)
        store_links = []
        ctx['show_events_link'] = stores.admin_console_store.probe_events
        store_links = []
        for store in stores.iter_events_url_store_for_user("probe", self.request.user):
            url = "{}?{}".format(
                reverse("probes:probe_events_store_redirect", args=(self.probe.pk,)),
                urlencode({"es": store.name,
                           "tr": ProbeEventsView.default_time_range})
            )
            store_links.append((url, store.name))
        ctx["store_links"] = store_links
        return ctx

    def get_template_names(self):
        if self.probe.loaded:
            return [self.probe.template_name]
        else:
            return ["probes/syntax_error.html"]


class EventsMixin:
    permission_required = ("probes.view_probesource",)
    store_method_scope = "probe"

    def get_object(self, **kwargs):
        return get_object_or_404(ProbeSource, pk=kwargs['pk'])

    def get_fetch_kwargs_extra(self):
        return {"probe": self.object}

    def get_fetch_url(self):
        return reverse("probes:fetch_probe_events", args=(self.object.pk,))

    def get_redirect_url(self):
        return reverse("probes:probe_events", args=(self.object.pk,))

    def get_store_redirect_url(self):
        return reverse("probes:probe_events_store_redirect", args=(self.object.pk,))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["probe_source"] = self.object
        ctx["probe"] = Probe(self.object)
        return ctx


class ProbeEventsView(EventsMixin, EventsView):
    template_name = "probes/probe_events.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["breadcrumbs"] = [
            (reverse('probes:index'), 'Probes'),
            (reverse('probes:probe', args=(self.object.pk,)), self.object.name),
            (None, "events")
        ]
        return ctx


class FetchProbeEventsView(EventsMixin, FetchEventsView):
    pass


class ProbeEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    pass


class UpdateProbeView(PermissionRequiredMixin, UpdateView):
    permission_required = "probes.change_probesource"
    model = ProbeSource
    form_class = UpdateProbeForm
    template_name = "probes/form.html"

    def get_context_data(self, **kwargs):
        ctx = super(UpdateProbeView, self).get_context_data(**kwargs)
        probe_source = ctx['object']
        probe = Probe(probe_source)
        ctx["probe"] = probe
        return ctx


class DeleteProbeView(PermissionRequiredMixin, DeleteView):
    permission_required = "probes.delete_probesource"
    model = ProbeSource
    template_name = "probes/delete.html"
    success_url = reverse_lazy('probes:index')


class CloneProbeView(PermissionRequiredMixin, FormView):
    permission_required = "probes.add_probesource"
    template_name = "probes/clone.html"
    form_class = CloneProbeForm

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_initial(self):
        return {"name": "{} (clone)".format(self.probe_source.name)}

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['probe_source'] = self.probe_source
        return ctx

    def form_valid(self, form):
        new_probe = form.save(self.probe_source)
        return HttpResponseRedirect(new_probe.get_absolute_url())


# Filters


class AddFilterView(PermissionRequiredMixin, FormView):
    permission_required = "probes.change_probesource"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["pk"])
        self.probe = Probe(self.probe_source)
        self.section = kwargs["section"]
        return super().dispatch(request, *args, **kwargs)

    def get_template_names(self):
        return ["probes/{}_filter_form.html".format(self.section),
                "probes/filter_form.html"]

    def get_form_class(self):
        if self.section == "inventory":
            return InventoryFilterForm
        elif self.section == "metadata":
            return MetadataFilterForm
        elif self.section == "payload":
            return PayloadFilterFormSet

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['section'] = self.section
        ctx['add_filter'] = True
        return ctx

    def form_valid(self, form):
        self.probe_source.append_filter(self.section,
                                        form.get_serialized_filter())
        return super().form_valid(form)

    def get_success_url(self):
        return self.probe_source.get_filters_absolute_url()


class UpdateFilterView(PermissionRequiredMixin, FormView):
    permission_required = "probes.change_probesource"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["pk"])
        self.probe = Probe(self.probe_source)
        self.section = kwargs["section"]
        self.filter_id = int(kwargs["filter_id"])
        try:
            self.filter = getattr(self.probe, "{}_filters".format(self.section), [])[self.filter_id]
        except IndexError:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_template_names(self):
        return ["probes/{}_filter_form.html".format(self.section),
                "probes/filter_form.html"]

    def get_form_class(self):
        if self.section == "inventory":
            return InventoryFilterForm
        elif self.section == "metadata":
            return MetadataFilterForm
        elif self.section == "payload":
            return PayloadFilterFormSet

    def get_initial(self):
        return self.get_form_class().get_initial(self.filter)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['section'] = self.section
        ctx['add_filter'] = False
        return ctx

    def form_valid(self, form):
        self.probe_source.update_filter(self.section, self.filter_id,
                                        form.get_serialized_filter())
        return super().form_valid(form)

    def get_success_url(self):
        return self.probe_source.get_filters_absolute_url()


class DeleteFilterView(PermissionRequiredMixin, TemplateView):
    permission_required = "probes.change_probesource"
    template_name = "probes/delete_filter.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["pk"])
        self.probe = Probe(self.probe_source)
        self.filter_id = int(kwargs["filter_id"])
        self.section = kwargs["section"]
        try:
            self.filter = getattr(self.probe, "{}_filters".format(self.section), [])[self.filter_id]
        except IndexError:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['section'] = self.section
        return ctx

    def post(self, request, *args, **kwargs):
        self.probe_source.delete_filter(self.section, self.filter_id)
        return HttpResponseRedirect(self.probe_source.get_filters_absolute_url())
