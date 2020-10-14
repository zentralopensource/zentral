from datetime import datetime, timedelta
import logging
from math import ceil
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ObjectDoesNotExist
from django.urls import reverse, reverse_lazy
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views.generic import CreateView, DeleteView, FormView, ListView, TemplateView, UpdateView, View
from zentral.core.incidents.models import MachineIncident
from zentral.core.stores import frontend_store
from zentral.utils.prometheus import BasePrometheusMetricsView
from .forms import (MetaBusinessUnitForm,
                    MetaBusinessUnitSearchForm, MachineGroupSearchForm,
                    MergeMBUForm, MBUAPIEnrollmentForm, AddMBUTagForm, AddMachineTagForm,
                    CreateTagForm, UpdateTagForm,
                    MacOSAppSearchForm)
from .models import (BusinessUnit,
                     MetaBusinessUnit, MachineGroup,
                     MetaMachine,
                     MetaBusinessUnitTag, MachineTag, Tag, Taxonomy,
                     OSXApp, OSXAppInstance)
from .utils import (get_prometheus_inventory_metrics,
                    BundleFilter, BundleFilterForm,
                    MachineGroupFilter, MetaBusinessUnitFilter, OSXAppInstanceFilter,
                    MSQuery)


logger = logging.getLogger("zentral.contrib.inventory.views")


class MachineListView(LoginRequiredMixin, FormView):
    template_name = "inventory/machine_list.html"
    form_class = BundleFilterForm

    def get_object(self, **kwargs):
        return None

    def get_msquery(self, request):
        return MSQuery(request.GET)

    def dispatch(self, request, *args, **kwargs):
        try:
            self.object = self.get_object(**kwargs)
        except ObjectDoesNotExist:
            raise Http404
        self.msquery = self.get_msquery(request)
        if request.method == "GET":
            redirect_url = self.msquery.redirect_url()
            if redirect_url:
                return HttpResponseRedirect(redirect_url)
        return super().dispatch(request, *args, **kwargs)

    def get_list_title(self):
        return ""

    def get_breadcrumbs(self, **kwargs):
        return []

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['inventory'] = True
        # object
        ctx["object"] = self.object
        ctx['object_list_title'] = self.get_list_title()
        # msquery
        ctx["msquery"] = self.msquery
        # pagination / machines
        ctx["machines"] = self.msquery.fetch()
        ctx["grouping_links"] = self.msquery.grouping_links()
        if self.msquery.page > 1:
            qd = self.request.GET.copy()
            qd['page'] = self.msquery.page - 1
            ctx['previous_url'] = "?{}".format(qd.urlencode())
        if self.msquery.page * self.msquery.paginate_by < self.msquery.count():
            qd = self.request.GET.copy()
            qd['page'] = self.msquery.page + 1
            ctx['next_url'] = "?{}".format(qd.urlencode())
        # search form
        search_form_qd = self.request.GET.copy()
        for key in [f.get_query_kwarg() for f in self.msquery.filters if f.free_input]:
            search_form_qd.pop(key, None)
        ctx["search_form_qd"] = search_form_qd
        # breadcrumbs
        breadcrumbs = self.get_breadcrumbs(**kwargs)
        if breadcrumbs:
            num_pages = ceil(max(self.msquery.count(), 1) / self.msquery.paginate_by)
            _, anchor_text = breadcrumbs.pop()
            reset_qd = self.request.GET.copy()
            reset_qd.pop('page', None)
            reset_link = "?{}".format(reset_qd.urlencode())
            breadcrumbs.extend([(reset_link, anchor_text),
                                (None, "page {} of {}".format(self.msquery.page, num_pages))])
        ctx['breadcrumbs'] = breadcrumbs
        msquery_cqd = self.msquery.get_canonical_query_dict()
        ctx['export_links'] = []
        for fmt in ("xlsx", "zip"):
            export_qd = msquery_cqd.copy()
            export_qd["export_format"] = fmt
            ctx['export_links'].append((fmt,
                                        "{}?{}".format(reverse("inventory_api:machines_export"),
                                                       export_qd.urlencode())))
        return ctx

    def form_valid(self, form):
        f_kwargs = {}
        bundle_id = form.cleaned_data.get("bundle_id")
        bundle_name = form.cleaned_data.get("bundle_name")
        if bundle_id:
            f_kwargs["bundle_id"] = bundle_id
        elif bundle_name:
            f_kwargs["bundle_name"] = bundle_name
        self.msquery.add_filter(BundleFilter, **f_kwargs)
        return HttpResponseRedirect(self.msquery.get_url())


class IndexView(MachineListView):
    def get_breadcrumbs(self, **kwargs):
        return [(None, "Inventory machines")]


class GroupsView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/group_list.html"

    def get(self, request, *args, **kwargs):
        self.search_form = MachineGroupSearchForm(request.GET)
        return super(GroupsView, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(GroupsView, self).get_context_data(**kwargs)
        context['inventory'] = True
        qs = MachineGroup.objects.current()
        if self.search_form.is_valid():
            name = self.search_form.cleaned_data['name']
            if name:
                qs = qs.filter(name__icontains=name)
            source = self.search_form.cleaned_data['source']
            if source:
                qs = qs.filter(source=source)
        context['object_list'] = qs
        context['search_form'] = self.search_form
        breadcrumbs = []
        if self.search_form.is_valid() and len([i for i in self.search_form.cleaned_data.values() if i]):
            breadcrumbs.append((reverse('inventory:groups'), 'Inventory groups'))
            breadcrumbs.append((None, "Search"))
        else:
            breadcrumbs.append((None, "Inventory groups"))
        context['breadcrumbs'] = breadcrumbs
        return context


class GroupMachinesView(MachineListView):
    def get_object(self, **kwargs):
        return MachineGroup.objects.select_related('source').get(pk=kwargs['group_id'])

    def get_msquery(self, request):
        ms_query = super().get_msquery(request)
        ms_query.force_filter(MachineGroupFilter, hidden_value=self.object.pk)
        return ms_query

    def get_list_title(self):
        return "Group: {} - {}".format(self.object.source.name, self.object.name)

    def get_breadcrumbs(self, **kwargs):
        return [(reverse('inventory:groups'), 'Inventory groups'),
                (None, self.object.name)]


class OSXAppInstanceMachinesView(MachineListView):
    template_name = "inventory/macos_app_instance_machines.html"

    def get_object(self, **kwargs):
        return OSXAppInstance.objects.select_related('app').get(app__pk=kwargs['pk'],
                                                                pk=kwargs['osx_app_instance_id'])

    def get_msquery(self, request):
        ms_query = super().get_msquery(request)
        ms_query.force_filter(OSXAppInstanceFilter, hidden_value=self.object.pk)
        return ms_query

    def get_list_title(self):
        return "macOS app instance: {}".format(self.object.app)

    def get_breadcrumbs(self, **kwargs):
        return [(reverse('inventory:macos_apps'), 'macOS applications'),
                ((reverse('inventory:macos_app', args=(self.object.app.id,)), str(self.object.app))),
                (None, "Machines")]


class MBUView(LoginRequiredMixin, ListView):
    template_name = "inventory/mbu_list.html"
    paginate_by = 25

    def get(self, request, *args, **kwargs):
        self.search_form = MetaBusinessUnitSearchForm(request.GET)
        return super(MBUView, self).get(request, *args, **kwargs)

    def get_queryset(self, **kwargs):
        qs = MetaBusinessUnit.objects.all()
        if self.search_form.is_valid():
            name = self.search_form.cleaned_data['name']
            if name:
                qs = qs.filter(name__icontains=name)
            source = self.search_form.cleaned_data['source']
            if source:
                qs = qs.filter(businessunit__source=source)
            tag = self.search_form.cleaned_data['tag']
            if tag:
                qs = qs.filter(metabusinessunittag__tag=tag)
        return qs

    def get_context_data(self, **kwargs):
        context = super(MBUView, self).get_context_data(**kwargs)
        context['inventory'] = True
        context['search_form'] = self.search_form
        # pagination
        page = context['page_obj']
        if page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = page.next_page_number()
            context['next_url'] = "?{}".format(qd.urlencode())
        if page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = page.previous_page_number()
            context['previous_url'] = "?{}".format(qd.urlencode())
        # breadcrumbs
        breadcrumbs = []
        qd = self.request.GET.copy()
        qd.pop('page', None)
        reset_link = "?{}".format(qd.urlencode())
        if self.search_form.is_valid() and len([i for i in self.search_form.cleaned_data.values() if i]):
            breadcrumbs.append((reverse('inventory:mbu'), 'Inventory business units'))
            breadcrumbs.append((reset_link, "Search"))
        else:
            breadcrumbs.append((reset_link, "Inventory business units"))
        breadcrumbs.append((None, "page {} of {}".format(page.number, page.paginator.num_pages)))
        context['breadcrumbs'] = breadcrumbs
        return context


class ReviewMBUMergeView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/review_mbu_merge.html"

    def get_context_data(self, **kwargs):
        ctx = super(ReviewMBUMergeView, self).get_context_data(**kwargs)
        ctx['inventory'] = True
        ctx['meta_business_units'] = MetaBusinessUnit.objects.filter(id__in=self.request.GET.getlist('mbu_id'))
        return ctx


class MergeMBUView(LoginRequiredMixin, FormView):
    template_name = "inventory/merge_mbu.html"
    form_class = MergeMBUForm

    def form_valid(self, form):
        self.dest_mbu = form.merge()
        return super(MergeMBUView, self).form_valid(form)

    def get_success_url(self):
        return reverse('inventory:mbu_machines', args=(self.dest_mbu.id,))


class CreateMBUView(LoginRequiredMixin, CreateView):
    template_name = "inventory/edit_mbu.html"
    model = MetaBusinessUnit
    form_class = MetaBusinessUnitForm


class UpdateMBUView(LoginRequiredMixin, UpdateView):
    template_name = "inventory/edit_mbu.html"
    model = MetaBusinessUnit
    form_class = MetaBusinessUnitForm


class DeleteMBUView(LoginRequiredMixin, DeleteView):
    model = MetaBusinessUnit

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        try:
            self.object.delete()
        except ValueError:
            logger.exception("Could not delete MBU %s", self.object.pk)
        return HttpResponseRedirect(reverse('inventory:mbu'))


class MBUTagsView(LoginRequiredMixin, FormView):
    template_name = "inventory/mbu_tags.html"
    form_class = AddMBUTagForm

    def dispatch(self, request, *args, **kwargs):
        self.mbu = get_object_or_404(MetaBusinessUnit, pk=kwargs['pk'])
        return super(MBUTagsView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(MBUTagsView, self).get_context_data(**kwargs)
        context['inventory'] = True
        context['meta_business_unit'] = self.mbu
        context['tags'] = self.mbu.tags()
        context['color_presets'] = TAG_COLOR_PRESETS
        return context

    def get_form_kwargs(self, *args, **kwargs):
        kwargs = super(MBUTagsView, self).get_form_kwargs(*args, **kwargs)
        kwargs['meta_business_unit'] = self.mbu
        return kwargs

    def form_valid(self, form):
        form.save()
        return super(MBUTagsView, self).form_valid(form)

    def get_success_url(self):
        return reverse('inventory:mbu_tags', args=(self.mbu.id,))


class RemoveMBUTagView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        MetaBusinessUnitTag.objects.filter(tag__id=kwargs['tag_id'],
                                           meta_business_unit__id=kwargs['pk']).delete()
        return HttpResponseRedirect(reverse('inventory:mbu_tags', args=(kwargs['pk'],)))


class DetachBUView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/detach_bu.html"

    def dispatch(self, request, *args, **kwargs):
        self.bu = get_object_or_404(BusinessUnit,
                                    pk=kwargs['bu_id'],
                                    meta_business_unit__id=kwargs['pk'])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['inventory'] = True
        context['bu'] = self.bu
        context['mbu'] = self.bu.meta_business_unit
        return context

    def post(self, *args, **kwargs):
        mbu = self.bu.detach()
        return HttpResponseRedirect(mbu.get_absolute_url())


class MBUAPIEnrollmentView(LoginRequiredMixin, UpdateView):
    template_name = "inventory/mbu_api_enrollment.html"
    form_class = MBUAPIEnrollmentForm
    queryset = MetaBusinessUnit.objects.all()

    def form_valid(self, form):
        self.mbu = form.enable_api_enrollment()
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        return reverse('inventory:mbu_machines', args=(self.mbu.id,))


class MBUMachinesView(MachineListView):
    template_name = "inventory/mbu_machines.html"

    def get_object(self, **kwargs):
        return MetaBusinessUnit.objects.get(pk=kwargs['pk'])

    def get_msquery(self, request):
        ms_query = super().get_msquery(request)
        ms_query.force_filter(MetaBusinessUnitFilter, hidden_value=self.object.pk)
        return ms_query

    def get_list_title(self):
        return "BU: {}".format(self.object.name)

    def get_breadcrumbs(self, **kwargs):
        return [(reverse('inventory:mbu'), 'Inventory business units'),
                (None, self.object.name)]


class MachineView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/machine_detail.html"

    def get_context_data(self, **kwargs):
        context = super(MachineView, self).get_context_data(**kwargs)
        context['inventory'] = True
        context['machine'] = machine = MetaMachine.from_urlsafe_serial_number(context['urlsafe_serial_number'])
        context['machine_snapshots'] = sorted(
            [(ms.source.get_display_name(), ms) for ms in machine.snapshots],
            key=lambda t: t[0].lower()
        )
        machine_snapshots_count = len(context['machine_snapshots'])
        if machine_snapshots_count:
            context['max_source_tab_with'] = 100 // machine_snapshots_count
        context['serial_number'] = machine.serial_number
        prepared_heartbeats = []
        try:
            last_machine_heartbeats = frontend_store.get_last_machine_heartbeats(machine.serial_number)
        except Exception:
            logger.exception("Could not get machine heartbeats")
        else:
            for event_class, source_name, ua_max_dates in last_machine_heartbeats:
                heartbeat_timeout = event_class.heartbeat_timeout
                if heartbeat_timeout:
                    heartbeat_timeout = timedelta(seconds=heartbeat_timeout)
                ua_max_dates.sort(key=lambda t: (t[1], t[0]), reverse=True)
                date_class = None
                if ua_max_dates:
                    # should always be the case
                    all_ua_max_date = timezone.make_naive(ua_max_dates[0][1])
                    if heartbeat_timeout:
                        if datetime.utcnow() - all_ua_max_date > heartbeat_timeout:
                            date_class = "danger"
                        else:
                            date_class = "success"
                prepared_heartbeats.append(
                    (event_class.get_event_type_display(),
                     source_name, ua_max_dates, date_class)
                )
            prepared_heartbeats.sort()
        context['heartbeats'] = prepared_heartbeats
        return context


class ArchiveMachineView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/archive_machine.html"

    def dispatch(self, request, *args, **kwargs):
        self.machine = MetaMachine.from_urlsafe_serial_number(kwargs['urlsafe_serial_number'])
        return super(ArchiveMachineView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(ArchiveMachineView, self).get_context_data(**kwargs)
        context['inventory'] = True
        context['machine'] = self.machine
        return context

    def post(self, request, *args, **kwargs):
        self.machine.archive()
        return redirect('inventory:index')


class MachineEventSet(object):
    def __init__(self, machine_serial_number, event_type=None):
        self.machine_serial_number = machine_serial_number
        self.event_type = event_type
        self.store = frontend_store
        self._count = None

    def count(self):
        if self._count is None:
            self._count = self.store.machine_events_count(self.machine_serial_number, self.event_type)
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
        for event in self.store.machine_events_fetch(self.machine_serial_number, start, stop - start, self.event_type):
            if not self.event_type:
                link = "?event_type={}".format(event.event_type)
            else:
                link = None
            yield event, link


class MachineEventsView(LoginRequiredMixin, ListView):
    template_name = "inventory/machine_events.html"
    paginate_by = 10

    def get_context_data(self, **kwargs):
        context = super(MachineEventsView, self).get_context_data(**kwargs)
        context["machine"] = self.machine
        context["serial_number"] = self.serial_number
        # pagination
        page = context['page_obj']
        if page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = page.next_page_number()
            context['next_url'] = "?{}".format(qd.urlencode())
        if page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = page.previous_page_number()
            context['previous_url'] = "?{}".format(qd.urlencode())
        event_types = []
        total_events = 0

        # event types selection
        request_event_type = self.request.GET.get('event_type')
        for event_type, count in frontend_store.machine_events_types_with_usage(
                self.serial_number).items():
            total_events += count
            event_types.append((event_type,
                                request_event_type == event_type,
                                "{} ({})".format(event_type.replace('_', ' ').title(), count)))
        event_types.sort()
        event_types.insert(0, ('',
                               request_event_type in [None, ''],
                               'All ({})'.format(total_events)))
        context['event_types'] = event_types
        return context

    def get_queryset(self):
        self.machine = MetaMachine.from_urlsafe_serial_number(self.kwargs["urlsafe_serial_number"])
        self.serial_number = self.machine.serial_number
        et = self.request.GET.get('event_type')
        return MachineEventSet(self.serial_number, et)


class MachineMacOSAppInstancesView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/machine_macos_app_instances.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['inventory'] = True
        context['machine'] = machine = MetaMachine.from_urlsafe_serial_number(context['urlsafe_serial_number'])
        context['serial_number'] = machine.serial_number
        return context


class MachineIncidentsView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/machine_incidents.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['inventory'] = True
        context['machine'] = machine = MetaMachine.from_urlsafe_serial_number(context['urlsafe_serial_number'])
        context['serial_number'] = machine.serial_number
        context['incidents'] = (MachineIncident.objects.select_related("incident__probe_source")
                                                       .filter(serial_number=machine.serial_number))
        return context


class MachineTagsView(LoginRequiredMixin, FormView):
    template_name = "inventory/machine_tags.html"
    form_class = AddMachineTagForm

    def dispatch(self, request, *args, **kwargs):
        self.machine = MetaMachine.from_urlsafe_serial_number(kwargs["urlsafe_serial_number"])
        self.msn = self.machine.serial_number
        return super(MachineTagsView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(MachineTagsView, self).get_context_data(**kwargs)
        context['inventory'] = True
        context['machine'] = self.machine
        context['color_presets'] = TAG_COLOR_PRESETS
        return context

    def get_form_kwargs(self, *args, **kwargs):
        kwargs = super(MachineTagsView, self).get_form_kwargs(*args, **kwargs)
        kwargs['machine_serial_number'] = self.msn
        return kwargs

    def form_valid(self, form):
        form.save()
        return super(MachineTagsView, self).form_valid(form)

    def get_success_url(self):
        return reverse('inventory:machine_tags', args=(self.machine.get_urlsafe_serial_number(),))


class RemoveMachineTagView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        machine = MetaMachine.from_urlsafe_serial_number(kwargs["urlsafe_serial_number"])
        MachineTag.objects.filter(tag__id=kwargs['tag_id'],
                                  serial_number=machine.serial_number).delete()
        return HttpResponseRedirect(reverse('inventory:machine_tags', args=(machine.get_urlsafe_serial_number(),)))


TAG_COLOR_PRESETS = {
    "green": "61bd4f",
    "yellow": "f2d600",
    "orange": "ffab4a",
    "red": "eb5a46",
    "purple": "c377e0",
    "blue": "0079bf",
    "sky": "00c2e0",
    "lime": "51e898",
    "pink": "ff80ce",
    "black": "4d4d4d",
    "grey": "b6bbbf"
}


class TagsView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/tag_index.html"

    def get_context_data(self, **kwargs):
        ctx = super(TagsView, self).get_context_data(**kwargs)
        ctx['inventory'] = True
        ctx['tag_list'] = list(Tag.objects.all())
        ctx['taxonomy_list'] = list(Taxonomy.objects.all())
        return ctx


class CreateTagView(LoginRequiredMixin, CreateView):
    model = Tag
    form_class = CreateTagForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['inventory'] = True
        ctx['color_presets'] = TAG_COLOR_PRESETS
        return ctx

    def get_success_url(self):
        return reverse('inventory:tags')


class UpdateTagView(LoginRequiredMixin, UpdateView):
    model = Tag
    form_class = UpdateTagForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['inventory'] = True
        ctx['color_presets'] = TAG_COLOR_PRESETS
        return ctx

    def get_success_url(self):
        return reverse('inventory:tags')


class DeleteTagView(LoginRequiredMixin, DeleteView):
    model = Tag
    success_url = reverse_lazy("inventory:tags")

    def get_context_data(self, **kwargs):
        ctx = super(DeleteTagView, self).get_context_data(**kwargs)
        ctx['links'] = self.object.links()
        return ctx


class CreateTaxonomyView(LoginRequiredMixin, CreateView):
    model = Taxonomy
    fields = ('meta_business_unit', 'name')

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['inventory'] = True
        return ctx

    def get_success_url(self):
        return reverse('inventory:tags')


class UpdateTaxonomyView(LoginRequiredMixin, UpdateView):
    model = Taxonomy
    fields = ('name',)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['inventory'] = True
        return ctx

    def get_success_url(self):
        return reverse('inventory:tags')


class DeleteTaxonomyView(LoginRequiredMixin, DeleteView):
    model = Taxonomy
    success_url = reverse_lazy("inventory:tags")

    def get_context_data(self, **kwargs):
        ctx = super(DeleteTaxonomyView, self).get_context_data(**kwargs)
        ctx['links'] = self.object.links()
        return ctx


class MacOSAppsView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/macos_apps.html"

    def get(self, request, *args, **kwargs):
        self.search_form = MacOSAppSearchForm(request.GET)
        return super(MacOSAppsView, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super(MacOSAppsView, self).get_context_data(**kwargs)
        ctx['inventory'] = True
        ctx['search_form'] = self.search_form
        if self.search_form.is_valid():
            (ctx['object_list'],
             ctx['total_objects'],
             previous_page,
             next_page,
             ctx['total_pages']) = self.search_form.search(limit=50)
            if next_page:
                qd = self.request.GET.copy()
                qd['page'] = next_page
                ctx['next_url'] = "?{}".format(qd.urlencode())
            if previous_page:
                qd = self.request.GET.copy()
                qd['page'] = previous_page
                ctx['previous_url'] = "?{}".format(qd.urlencode())
        qd = self.request.GET.copy()
        qd.pop('page', None)
        reset_link = "?{}".format(qd.urlencode())
        breadcrumbs = []
        if self.search_form.is_valid() \
           and len([i for k, i in self.search_form.cleaned_data.items() if i and not k == 'page']):
            breadcrumbs.append((reverse('inventory:macos_apps'), "macOS applications"))
            breadcrumbs.append((reset_link, "Search"))
        else:
            breadcrumbs.append((reset_link, "macOS applications"))
        breadcrumbs.append((None, "page {} of {}".format(self.search_form.cleaned_data['page'],
                                                         ctx.get('total_pages', 1))))
        ctx['breadcrumbs'] = breadcrumbs
        return ctx


class MacOSAppView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/macos_app.html"

    def get_context_data(self, **kwargs):
        ctx = super(MacOSAppView, self).get_context_data(**kwargs)
        macos_app = get_object_or_404(OSXApp, pk=kwargs['pk'])
        ctx['macos_app'] = macos_app
        instance_qs = macos_app.current_instances()
        ctx['instance_count'] = instance_qs.count()
        ctx['instances'] = instance_qs.order_by('id')
        ctx['inventory'] = True
        return ctx


class PrometheusMetricsView(BasePrometheusMetricsView):
    def get_registry(self):
        return get_prometheus_inventory_metrics()
