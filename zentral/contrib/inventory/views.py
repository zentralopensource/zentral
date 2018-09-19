from datetime import datetime, timedelta
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.core.urlresolvers import reverse, reverse_lazy
from django.db import connection
from django.http import HttpResponse, HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.utils.timezone import make_naive
from django.views.generic import CreateView, DeleteView, FormView, ListView, TemplateView, UpdateView, View
from zentral.core.stores import frontend_store
from zentral.conf import settings
from .forms import (MetaBusinessUnitForm,
                    MetaBusinessUnitSearchForm, MachineGroupSearchForm, MachineSearchForm,
                    MergeMBUForm, MBUAPIEnrollmentForm, AddMBUTagForm, AddMachineTagForm,
                    CreateTagForm,
                    MacOSAppSearchForm)
from .models import (BusinessUnit,
                     MetaBusinessUnit, MachineGroup,
                     MachineSnapshot, MetaMachine,
                     MetaBusinessUnitTag, MachineTag, Tag, Taxonomy,
                     OSXApp, OSXAppInstance)
from .utils import (get_prometheus_inventory_metrics,
                    mbu_dashboard_bundle_data, mbu_dashboard_machine_data,
                    prometheus_metrics_content_type)


class MachineListView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/machine_list.html"

    def get_object(self, **kwargs):
        return None

    def get_list_title(self, **kwargs):
        return ""

    def get_breadcrumbs(self, **kwargs):
        return []

    def get(self, request, *args, **kwargs):
        self.search_form = MachineSearchForm(request.GET)
        return super(MachineListView, self).get(request, *args, **kwargs)

    def get_extra_joins(self):
        return []

    def get_extra_wheres(self):
        return []

    def _get_filtered_serial_numbers(self):
        extra_joins = self.get_extra_joins()
        extra_wheres = self.get_extra_wheres()
        query_args = {}
        if self.search_form.is_valid():
            cleaned_data = self.search_form.cleaned_data
            serial_number = cleaned_data['serial_number']
            if serial_number:
                extra_wheres.append("and serial_number ~* %(serial_number)s")
                query_args['serial_number'] = serial_number
            name = cleaned_data['name']
            if name:
                extra_wheres.append("and (si.id is not null and computer_name ~* %(name)s)")
                query_args['name'] = name
            source = cleaned_data['source']
            if source:
                extra_wheres.append("and ms.source_id = %(source_id)s")
                query_args['source_id'] = source.id
            platform = cleaned_data['platform']
            if platform:
                extra_wheres.append("and ms.platform = %(platform)s")
                query_args['platform'] = platform
            ms_type = cleaned_data['type']
            if ms_type:
                extra_wheres.append("and ms.type = %(type)s")
                query_args['type'] = ms_type
            tag = cleaned_data['tag']
            if tag is not None:
                extra_wheres.append("and (serial_number in "
                                    " (select serial_number from inventory_machinetag where tag_id=%(tag_id)s) "
                                    "or ms.business_unit_id in "
                                    " (select bu.id from inventory_businessunit as bu "
                                    "  join inventory_metabusinessunittag as mbut "
                                    "  on (mbut.meta_business_unit_id = bu.meta_business_unit_id) "
                                    "  where mbut.tag_id=%(tag_id)s))")
                query_args['tag_id'] = tag
        query = ("select ms.serial_number as serial_number, max(si.computer_name) as computer_name "
                 "from inventory_machinesnapshot as ms "
                 "left join inventory_systeminfo as si on (si.id = ms.system_info_id) "
                 "{} "
                 "where ms.id in (select machine_snapshot_id from inventory_currentmachinesnapshot) {} "
                 "group by serial_number "
                 "order by computer_name;")
        query = query.format(" ".join(extra_joins), " ".join(extra_wheres))
        cursor = connection.cursor()
        cursor.execute(query, query_args)
        return [t[0] for t in cursor.fetchall()]

    def _get_serial_number_page(self):
        paginator = Paginator(self._get_filtered_serial_numbers(), 50)
        page_num = self.request.GET.get('page')
        try:
            return paginator.page(page_num)
        except PageNotAnInteger:
            return paginator.page(1)
        except EmptyPage:
            return paginator.page(paginator.num_pages)

    def get_context_data(self, **kwargs):
        context = super(MachineListView, self).get_context_data(**kwargs)
        self.object = self.get_object(**kwargs)
        context['object'] = self.object
        context['inventory'] = True
        serial_number_page = self._get_serial_number_page()
        ms_dict = {}
        for ms in (MachineSnapshot.objects.current()
                   .filter(serial_number__in=[msn for msn in serial_number_page])):
            ms_dict.setdefault(ms.serial_number, []).append(ms)
        context['object_list'] = [MetaMachine(msn, ms_dict[msn]) for msn in serial_number_page]
        # pagination
        context['total_objects'] = serial_number_page.paginator.count
        if serial_number_page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = serial_number_page.next_page_number()
            context['next_url'] = "?{}".format(qd.urlencode())
        if serial_number_page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = serial_number_page.previous_page_number()
            context['previous_url'] = "?{}".format(qd.urlencode())
        context['object_list_title'] = self.get_list_title(**kwargs)
        context['search_form'] = self.search_form
        breadcrumbs = self.get_breadcrumbs(**kwargs)
        if breadcrumbs:
            _, anchor_text = breadcrumbs.pop()
            qd = self.request.GET.copy()
            qd.pop('page', None)
            reset_link = "?{}".format(qd.urlencode())
            breadcrumbs.extend([(reset_link, anchor_text),
                                (None, "page {} of {}".format(serial_number_page.number,
                                                              serial_number_page.paginator.num_pages))])
        context['breadcrumbs'] = breadcrumbs
        return context


class IndexView(MachineListView):
    def get_breadcrumbs(self, **kwargs):
        l = []
        if self.search_form.is_valid() and len([i for i in self.search_form.cleaned_data.values() if i]):
            l.append((reverse('inventory:index'), "Inventory machines"))
            l.append((None, "Machine search"))
        else:
            l.append((None, "Inventory machines"))
        return l


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
        l = []
        if self.search_form.is_valid() and len([i for i in self.search_form.cleaned_data.values() if i]):
            l.append((reverse('inventory:groups'), 'Inventory groups'))
            l.append((None, "Search"))
        else:
            l.append((None, "Inventory groups"))
        context['breadcrumbs'] = l
        return context


class GroupMachinesView(MachineListView):
    def get_object(self, **kwargs):
        return MachineGroup.objects.select_related('source').get(pk=kwargs['group_id'])

    def get_extra_joins(self):
        return ["join inventory_machinesnapshot_groups as msg "
                "on (msg.machinesnapshot_id = ms.id) "
                "join inventory_machinegroup as mg "
                "on (mg.id = msg.machinegroup_id)"]

    def get_extra_wheres(self):
        return ["and mg.id = %d" % self.object.id]

    def get_list_title(self, **kwargs):
        return "Group: {} - {}".format(self.object.source.name, self.object.name)

    def get_breadcrumbs(self, **kwargs):
        l = [(reverse('inventory:groups'), 'Inventory groups')]
        if self.search_form.is_valid() and len([i for i in self.search_form.cleaned_data.values() if i]):
            l.append((reverse('inventory:group_machines', args=(self.object.id,)), self.object.name))
            l.append((None, "Machine search"))
        else:
            l.append((None, self.object.name))
        return l


class OSXAppInstanceMachinesView(MachineListView):
    template_name = "inventory/macos_app_instance_machines.html"

    def get_object(self, **kwargs):
        return OSXAppInstance.objects.select_related('app').get(app__pk=kwargs['pk'], pk=kwargs['osx_app_instance_id'])

    def get_extra_joins(self):
        return ["join inventory_machinesnapshot_osx_app_instances as msoai "
                "on (msoai.machinesnapshot_id = ms.id) "]

    def get_extra_wheres(self):
        return ["and msoai.osxappinstance_id = %d" % self.object.id]

    def get_list_title(self, **kwargs):
        return "macOS app instance: {}".format(self.object.app)

    def get_breadcrumbs(self, **kwargs):
        l = [(reverse('inventory:macos_apps'), 'macOS applications'),
             ((reverse('inventory:macos_app', args=(self.object.app.id,)), str(self.object.app)))]
        if self.search_form.is_valid() and len([i for i in self.search_form.cleaned_data.values() if i]):
            l.append((None, "Machine search"))
        else:
            l.append((None, "Machines"))
        return l


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
        l = []
        qd = self.request.GET.copy()
        qd.pop('page', None)
        reset_link = "?{}".format(qd.urlencode())
        if self.search_form.is_valid() and len([i for i in self.search_form.cleaned_data.values() if i]):
            l.append((reverse('inventory:mbu'), 'Inventory business units'))
            l.append((reset_link, "Search"))
        else:
            l.append((reset_link, "Inventory business units"))
        l.append((None, "page {} of {}".format(page.number, page.paginator.num_pages)))
        context['breadcrumbs'] = l
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
        if self.object.can_be_deleted():
            self.object.delete()
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

    def get_extra_joins(self):
        return ["join inventory_businessunit as bu "
                "on (bu.id = ms.business_unit_id) "
                "join inventory_metabusinessunit as mbu "
                "on (mbu.id = bu.meta_business_unit_id)"]

    def get_extra_wheres(self):
        return ["and mbu.id = %d" % self.object.id]

    def get_list_title(self, **kwargs):
        return "BU: {}".format(self.object.name)

    def get_breadcrumbs(self, **kwargs):
        l = [(reverse('inventory:mbu'), 'Inventory business units')]
        if self.search_form.is_valid() and len([i for i in self.search_form.cleaned_data.values() if i]):
            l.append((reverse('inventory:mbu_machines', args=(self.object.id,)), self.object.name))
            l.append((None, "Machine search"))
        else:
            l.append((None, self.object.name))
        return l


class MBUDashboardBundleDataView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        mbu = get_object_or_404(MetaBusinessUnit, pk=kwargs["pk"])
        return JsonResponse({bundle_id: {"name": bundle_name,
                                         "config": chart_config}
                             for bundle_id, bundle_name, chart_config
                             in mbu_dashboard_bundle_data(mbu)})


class MBUDashboardMachineDataView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        mbu = get_object_or_404(MetaBusinessUnit, pk=kwargs["pk"])
        return JsonResponse({doughnut_id: {"name": doughnut_name,
                                           "config": chart_config}
                             for doughnut_id, doughnut_name, chart_config
                             in mbu_dashboard_machine_data(mbu)})


class MachineView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/machine_detail.html"

    def get_context_data(self, **kwargs):
        context = super(MachineView, self).get_context_data(**kwargs)
        context['inventory'] = True
        context['machine'] = machine = MetaMachine(context['serial_number'])
        prepared_heartbeats = []
        last_machine_heartbeats = frontend_store.get_last_machine_heartbeats(machine.serial_number)
        for event_class, source_name, ua_max_dates in last_machine_heartbeats:
            heartbeat_timeout = event_class.heartbeat_timeout
            if heartbeat_timeout:
                heartbeat_timeout = timedelta(seconds=heartbeat_timeout)
            ua_max_dates.sort(key=lambda t: (t[1], t[0]), reverse=True)
            date_class = None
            if ua_max_dates:
                # should always be the case
                all_ua_max_date = make_naive(ua_max_dates[0][1])
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
        self.machine = MetaMachine(kwargs['serial_number'])
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
        context["serial_number"] = self.serial_number
        context["machine"] = MetaMachine(self.serial_number)
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
        self.serial_number = self.kwargs['serial_number']
        et = self.request.GET.get('event_type')
        return MachineEventSet(self.serial_number, et)


class MachineTagsView(LoginRequiredMixin, FormView):
    template_name = "inventory/machine_tags.html"
    form_class = AddMachineTagForm

    def dispatch(self, request, *args, **kwargs):
        self.msn = kwargs['serial_number']
        return super(MachineTagsView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(MachineTagsView, self).get_context_data(**kwargs)
        context['inventory'] = True
        context['machine'] = MetaMachine(self.msn)
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
        return reverse('inventory:machine_tags', args=(self.msn,))


class RemoveMachineTagView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        MachineTag.objects.filter(tag__id=kwargs['tag_id'],
                                  serial_number=kwargs['serial_number']).delete()
        return HttpResponseRedirect(reverse('inventory:machine_tags', args=(kwargs['serial_number'],)))


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
    fields = ('name', 'color')

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


class PrometheusMetricsView(View):
    def get(self, request, *args, **kwargs):
        bearer_token = settings['apps']['zentral.contrib.inventory'].get('prometheus_bearer_token')
        if bearer_token and \
           request.META.get('HTTP_AUTHORIZATION') == "Bearer {}".format(bearer_token):
            return HttpResponse(get_prometheus_inventory_metrics(),
                                content_type=prometheus_metrics_content_type)
        else:
            return HttpResponseForbidden()
