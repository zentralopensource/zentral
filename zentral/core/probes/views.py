import logging
from django.core.urlresolvers import reverse, reverse_lazy
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.views.generic import DetailView, ListView, TemplateView
from django.views.generic.edit import DeleteView, FormView, UpdateView
from zentral.core.stores import frontend_store
from .forms import CreateProbeForm, ProbeSearchForm, InventoryFilterForm, MetadataFilterForm, PayloadFilterFormSet
from .models import ProbeSource

logger = logging.getLogger("zentral.core.probes.views")


class IndexView(ListView):
    model = ProbeSource
    paginate_by = 50
    template_name = "core/probes/index.html"

    def get(self, request, *args, **kwargs):
        qd = self.request.GET.copy()
        if 'status' not in qd:
            qd['status'] = 'ACTIVE'
        self.form = ProbeSearchForm(qd)
        self.form.is_valid()
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return self.form.get_queryset()

    def get_context_data(self, **kwargs):
        ctx = super(IndexView, self).get_context_data(**kwargs)
        ctx['probes'] = True
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
            bc.append((reverse("probes:index"), "Probes"))
            bc.append((reset_link, "Search"))
        else:
            bc.append((reset_link, "Probes"))
        bc.append((None, "page {} of {}".format(page.number, page.paginator.num_pages)))
        ctx["breadcrumbs"] = bc
        return ctx


class CreateProbeView(FormView):
    form_class = CreateProbeForm
    template_name = "core/probes/form.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['probes'] = True
        return ctx

    def form_valid(self, form):
        probe_source = form.save()
        return HttpResponseRedirect(probe_source.get_absolute_url())


class ProbeView(DetailView):
    model = ProbeSource

    def get_context_data(self, **kwargs):
        ctx = super(ProbeView, self).get_context_data(**kwargs)
        ctx['probes'] = True
        ctx['probe'] = self.probe = self.object.load()
        ctx['add_action_urls'] = [
            (action.name, reverse("probes:edit_action", args=(self.object.id, action.name)))
            for action in self.probe.not_configured_actions()
        ]
        return ctx

    def get_template_names(self):
        return [self.probe.template_name]


class ProbeEventSet(object):
    def __init__(self, probe):
        self.probe = probe
        self.store = frontend_store
        self._count = None

    def count(self):
        if self._count is None:
            self._count = self.store.probe_events_count(self.probe,
                                                        **self.probe.get_extra_event_search_dict())
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
        return self.store.probe_events_fetch(self.probe, start, stop - start,
                                             **self.probe.get_extra_event_search_dict())


class ProbeEventsView(ListView):
    template_name = "core/probes/probe_events.html"
    paginate_by = 10

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs['pk'])
        self.probe = self.probe_source.load()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['probes'] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
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
        return ProbeEventSet(self.probe)


class UpdateProbeView(UpdateView):
    model = ProbeSource
    fields = ['name', 'status', 'description']
    template_name = "core/probes/form.html"

    def get_context_data(self, **kwargs):
        ctx = super(UpdateProbeView, self).get_context_data(**kwargs)
        ctx['probes'] = True
        probe_source = ctx['object']
        probe = probe_source.load()
        ctx["probe"] = probe
        return ctx


class DeleteProbeView(DeleteView):
    model = ProbeSource
    template_name = "core/probes/delete.html"
    success_url = reverse_lazy('probes:index')

    def get_context_data(self, **kwargs):
        ctx = super(DeleteProbeView, self).get_context_data(**kwargs)
        ctx['inventory'] = True
        return ctx


class EditActionView(FormView):
    template_name = "core/probes/action_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["pk"])
        self.probe = self.probe_source.load()
        from zentral.core.actions import actions as available_actions
        try:
            self.action = available_actions[kwargs["action"]]
        except KeyError:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_form_class(self):
        return self.action.action_form_class

    def get_initial(self):
        for action, action_config_d in self.probe.actions:
            if action.name == self.action.name:
                self.add_action = False
                return action_config_d or {}
        self.add_action = True
        return {}

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["config_d"] = self.action.config_d
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['action'] = self.action
        ctx['add_action'] = self.add_action
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        return ctx

    def form_valid(self, form):
        self.probe_source.update_action(self.action.name,
                                        form.get_action_config_d())
        return super().form_valid(form)

    def get_success_url(self):
        return self.probe_source.get_actions_absolute_url()


class DeleteActionView(TemplateView):
    template_name = "core/probes/delete_action.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["pk"])
        self.probe = self.probe_source.load()
        from zentral.core.actions import actions as available_actions
        try:
            self.action = available_actions[kwargs["action"]]
        except KeyError:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['action'] = self.action
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        return ctx

    def post(self, request, *args, **kwargs):
        self.probe_source.delete_action(self.action.name)
        return HttpResponseRedirect(self.probe_source.get_actions_absolute_url())


class AddFilterView(FormView):

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["pk"])
        self.probe = self.probe_source.load()
        self.section = kwargs["section"]
        return super().dispatch(request, *args, **kwargs)

    def get_template_names(self):
        return ["core/probes/{}_filter_form.html".format(self.section),
                "core/probes/filter_form.html"]

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
                                        form.get_filter_d())
        return super().form_valid(form)

    def get_success_url(self):
        return self.probe_source.get_filters_absolute_url()


class UpdateFilterView(FormView):

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["pk"])
        self.probe = self.probe_source.load()
        self.section = kwargs["section"]
        self.filter_id = int(kwargs["filter_id"])
        try:
            self.filter = getattr(self.probe, "{}_filters".format(self.section), [])[self.filter_id]
        except IndexError:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_template_names(self):
        return ["core/probes/{}_filter_form.html".format(self.section),
                "core/probes/filter_form.html"]

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
                                        form.get_filter_d())
        return super().form_valid(form)

    def get_success_url(self):
        return self.probe_source.get_filters_absolute_url()


class DeleteFilterView(TemplateView):
    template_name = "core/probes/delete_filter.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["pk"])
        self.probe = self.probe_source.load()
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
