import logging
from django import forms
from django.urls import reverse, reverse_lazy
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import Http404, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.generic import DeleteView, DetailView, FormView, ListView, TemplateView, UpdateView, View
from zentral.core.stores import frontend_store
from zentral.utils.charts import make_dataset
from .feeds import FeedError, sync_feed
from .forms import (CreateProbeForm, ProbeSearchForm,
                    InventoryFilterForm, MetadataFilterForm, PayloadFilterFormSet,
                    AddFeedForm, ImportFeedProbeForm,
                    CloneProbeForm, UpdateProbeForm)
from .models import Feed, FeedProbe, ProbeSource

logger = logging.getLogger("zentral.core.probes.views")


class IndexView(LoginRequiredMixin, ListView):
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


class CreateProbeView(LoginRequiredMixin, FormView):
    form_class = CreateProbeForm
    template_name = "core/probes/form.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['probes'] = True
        ctx['title'] = "Create event probe"
        return ctx

    def form_valid(self, form):
        probe_source = form.save()
        return HttpResponseRedirect(probe_source.get_absolute_url())


class ProbeView(LoginRequiredMixin, DetailView):
    model = ProbeSource

    def get_context_data(self, **kwargs):
        ctx = super(ProbeView, self).get_context_data(**kwargs)
        ctx['probes'] = True
        ctx['probe'] = self.probe = self.object.load()
        if self.probe.loaded:
            ctx['add_action_urls'] = [
                (action.name, reverse("probes:edit_action", args=(self.object.id, action.name)))
                for action in self.probe.not_configured_actions()
            ]
        return ctx

    def get_template_names(self):
        if self.probe.loaded:
            return [self.probe.template_name]
        else:
            return ["core/probes/syntax_error.html"]


class ProbeDashboardView(LoginRequiredMixin, DetailView):
    model = ProbeSource
    template_name = "core/probes/probe_dashboard.html"

    def get_context_data(self, **kwargs):
        ctx = super(ProbeDashboardView, self).get_context_data(**kwargs)
        ctx['probes'] = True
        ctx['probe'] = self.probe = self.object.load()
        if self.probe.loaded:
            ctx['aggregations'] = self.probe.get_aggregations()
        return ctx


class ProbeDashboardDataView(LoginRequiredMixin, View):
    INTERVAL_DATE_FORMAT = {
        "hour": "%H:%M",
        "day": "%d/%m",
        "week": "%d/%m",
        "month": "%m/%y",
    }

    def get(self, response, *args, **kwargs):
        probe_source = get_object_or_404(ProbeSource, pk=kwargs["pk"])
        probe = probe_source.load()
        charts = {}
        for field, results in frontend_store.probe_events_aggregations(probe,
                                                                       **probe.get_extra_event_search_dict()).items():
            a_type = results["type"]
            if a_type == "table":
                aggregation = probe.get_aggregations()[field]
                columns = aggregation["columns"]
                data = []
                for row in results["values"]:
                    for k, v in row.items():
                        if v is None:
                            row[k] = "-"
                    data.append(row)
                top_results = aggregation.get("top", False)
                if not top_results:
                    data.sort(key=lambda d: [d[fn].lower() for fn, _ in columns])
                labels = [l for _, l in columns]
                labels.append("Event count")
                chart_config = {
                    "type": "table",
                    "data": {
                        "labels": labels,
                        "datasets": [
                            {"data": data}
                        ]
                    }
                }
            elif a_type == "terms":
                chart_config = {
                    "type": "doughnut",
                    "data": {
                        "labels": ["Other" if l is None else l for l, _ in results["values"]],
                        "datasets": [make_dataset([v for _, v in results["values"]])],
                    }
                }
            elif a_type == "date_histogram":
                date_format = self.INTERVAL_DATE_FORMAT.get(results["interval"], "day")
                chart_config = {
                    "type": "bar",
                    "data": {
                        "labels": [l.strftime(date_format) for l, _ in results["values"]],
                        "datasets": [make_dataset([v for _, v in results["values"]],
                                                  cycle_colors=False,
                                                  label="event number")]
                    }
                }
            else:
                logger.error("Unknown aggregation type %s", a_type)
                continue
            charts[field] = chart_config
        return JsonResponse(charts)


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


class ProbeEventsView(LoginRequiredMixin, ListView):
    template_name = "core/probes/probe_events.html"
    paginate_by = 10

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs['pk'])
        self.probe = self.probe_source.load()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = {
            "probes": True,
            "probe_source": self.probe_source,
            "probe": self.probe
        }
        try:
            ctx.update(super().get_context_data(**kwargs))
        except Exception:
            # probably a store error
            logger.exception("Could not fetch probe %s events", self.probe_source.pk)
            ctx["error"] = "Could not fetch the probe events"

        # pagination
        # previous / next links
        page = ctx.get('page_obj')
        if page is not None and page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = page.next_page_number()
            ctx['next_url'] = "?{}".format(qd.urlencode())
        if page is not None and page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = page.previous_page_number()
            ctx['previous_url'] = "?{}".format(qd.urlencode())

        # breadcrumbs
        bc = [(reverse('probes:index'), 'Probes'),
              (reverse('probes:probe', args=(self.probe.pk,)), self.probe.name)]
        if page is not None and page.number > 1:
            qd = self.request.GET.copy()
            qd.pop("page", None)
            reset_link = "?{}".format(qd.urlencode())
        else:
            reset_link = None
        if page is not None and page.paginator.count:
            count = page.paginator.count
            pluralize = min(1, count - 1) * 's'
            bc.extend([(reset_link, '{} event{}'.format(count, pluralize)),
                       (None, "page {} of {}".format(page.number, page.paginator.num_pages))])
        else:
            # no events
            if "error" not in ctx:
                label = "no events found"
                ctx["error"] = label
            else:
                label = "error"
            bc.append((None, label))
        ctx['breadcrumbs'] = bc

        return ctx

    def get_queryset(self):
        return ProbeEventSet(self.probe)


class UpdateProbeView(LoginRequiredMixin, UpdateView):
    model = ProbeSource
    form_class = UpdateProbeForm
    template_name = "core/probes/form.html"

    def get_context_data(self, **kwargs):
        ctx = super(UpdateProbeView, self).get_context_data(**kwargs)
        ctx['probes'] = True
        probe_source = ctx['object']
        probe = probe_source.load()
        ctx["probe"] = probe
        return ctx


class DeleteProbeView(LoginRequiredMixin, DeleteView):
    model = ProbeSource
    template_name = "core/probes/delete.html"
    success_url = reverse_lazy('probes:index')

    def get_context_data(self, **kwargs):
        ctx = super(DeleteProbeView, self).get_context_data(**kwargs)
        ctx['probes'] = True
        return ctx


class CloneProbeView(LoginRequiredMixin, FormView):
    template_name = "core/probes/clone.html"
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


class ReviewProbeUpdateView(LoginRequiredMixin, TemplateView):
    template_name = "core/probes/review_update.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data()
        ctx["probes"] = True
        ctx["probe_source"] = self.probe_source
        ctx["update_diff"] = self.probe_source.update_diff()
        return ctx

    def post(self, request, *args, **kwargs):
        action = request.POST["action"]
        if action == "skip":
            self.probe_source.skip_update()
            messages.warning(request, "Probe update skipped")
        elif action == "apply":
            self.probe_source.apply_update()
            messages.success(request, "Probe updated")
        return HttpResponseRedirect(self.probe_source.get_absolute_url())


# Actions


class EditActionView(LoginRequiredMixin, FormView):
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


class DeleteActionView(LoginRequiredMixin, TemplateView):
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


# Filters


class AddFilterView(LoginRequiredMixin, FormView):

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
                                        form.get_serialized_filter())
        return super().form_valid(form)

    def get_success_url(self):
        return self.probe_source.get_filters_absolute_url()


class UpdateFilterView(LoginRequiredMixin, FormView):

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
                                        form.get_serialized_filter())
        return super().form_valid(form)

    def get_success_url(self):
        return self.probe_source.get_filters_absolute_url()


class DeleteFilterView(LoginRequiredMixin, TemplateView):
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


# Item views, used by other probes


class BaseProbeItemView(LoginRequiredMixin, FormView):
    probe_item_attribute = None
    success_anchor = None
    permission = None

    def do_setup(self, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.redirect_url = self.probe_source.get_absolute_url(self.success_anchor)
        self.probe = self.probe_source.load()
        if self.permission and not getattr(self.probe, self.permission):
            return HttpResponseRedirect(self.redirect_url)

    def dispatch(self, request, *args, **kwargs):
        response = self.do_setup(**kwargs)
        if response:
            return response
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["probes"] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['add_item'] = False
        ctx['cancel_url'] = self.redirect_url
        return ctx

    def get_success_url(self):
        return self.redirect_url

    def form_valid(self, form):
        item_d = form.get_item_d()
        func = self.get_update_func(item_d)
        self.probe_source.update_body(func)
        return super().form_valid(form)


class AddProbeItemView(BaseProbeItemView):
    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["add_item"] = True
        return ctx

    def get_update_func(self, item_d):
        def func(probe_d):
            items = probe_d.setdefault(self.probe_item_attribute, [])
            items.append(item_d)
        return func


class EditProbeItemView(BaseProbeItemView):
    item_pk_kwarg = None

    def do_setup(self, **kwargs):
        response = super().do_setup(**kwargs)
        if response:
            return response
        self.item_id = int(kwargs[self.item_pk_kwarg])
        self.items = getattr(self.probe, self.probe_item_attribute, [])
        try:
            self.item = self.items[self.item_id]
        except IndexError:
            return HttpResponseRedirect(self.redirect_url)


class UpdateProbeItemView(EditProbeItemView):
    def get_initial(self):
        return self.form_class.get_initial(self.item)

    def get_update_func(self, item_d):
        def func(probe_d):
            probe_d[self.probe_item_attribute][self.item_id] = item_d
        return func


class DeleteForm(forms.Form):
    def get_item_d(self):
        return {}


class DeleteProbeItemView(EditProbeItemView):
    form_class = DeleteForm

    def get_update_func(self, item_d):
        def func(probe_d):
            probe_d[self.probe_item_attribute].pop(self.item_id)
            if not probe_d[self.probe_item_attribute]:
                probe_d.pop(self.probe_item_attribute)
        return func


# feeds


class FeedsView(LoginRequiredMixin, ListView):
    template_name = "core/probes/feeds.html"
    model = Feed
    paginate_by = 10

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['probes'] = True
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
        bc = [(reverse('probes:index'), 'Probes')]
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
            bc.extend([(reset_link, '{} feed{}'.format(count, pluralize)),
                       (None, "page {} of {}".format(page.number, paginator.num_pages))])
        else:
            bc.append((None, "no feeds"))
        ctx['breadcrumbs'] = bc
        return ctx


class AddFeedView(LoginRequiredMixin, FormView):
    form_class = AddFeedForm
    template_name = "core/probes/add_feed.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['probes'] = True
        ctx['title'] = "Add feed"
        return ctx

    def form_valid(self, form):
        feed, created = form.save()
        return HttpResponseRedirect(feed.get_absolute_url())


class FeedView(LoginRequiredMixin, DetailView):
    template_name = "core/probes/feed.html"
    model = Feed

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['probes'] = True
        ctx['active_probes'] = list(self.object.feedprobe_set.filter(archived_at__isnull=True))
        return ctx


class SyncFeedView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        feed = get_object_or_404(Feed, pk=int(kwargs["pk"]))
        try:
            operations = sync_feed(feed)
        except FeedError as e:
            messages.error(request, "Could not sync feed. {}".format(e.message))
        else:
            if operations:
                msg = "Probes {}.".format(", ".join("{}: {}".format(l, v) for l, v in operations.items()))
            else:
                msg = "No changes."
            messages.info(request, "Sync OK. {}".format(msg))
        return HttpResponseRedirect(feed.get_absolute_url())


class DeleteFeedView(LoginRequiredMixin, DeleteView):
    model = Feed
    template_name = "core/probes/delete_feed.html"
    success_url = reverse_lazy('probes:feeds')

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['probes'] = True
        ctx['title'] = 'Delete feed'
        return ctx


class FeedProbeView(LoginRequiredMixin, DetailView):
    template_name = "core/probes/feed_probe.html"
    model = FeedProbe

    def get_object(self):
        return get_object_or_404(self.model, pk=self.kwargs["probe_id"], feed__pk=self.kwargs["pk"])

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["probe_sources"] = list(self.object.probesource_set.all())
        return ctx


class ImportFeedProbeView(LoginRequiredMixin, FormView):
    form_class = ImportFeedProbeForm
    template_name = "core/probes/import_feed_probe.html"

    def dispatch(self, request, *args, **kwargs):
        self.feed_probe = get_object_or_404(FeedProbe, pk=self.kwargs["probe_id"], feed__pk=self.kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['probes'] = True
        ctx['feed_probe'] = self.feed_probe
        ctx['feed'] = self.feed_probe.feed
        ctx['title'] = "Import feed probe"
        return ctx

    def form_valid(self, form):
        probe_source = form.save(self.feed_probe)
        return HttpResponseRedirect(probe_source.get_absolute_url())
