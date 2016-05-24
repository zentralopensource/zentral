from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.views import generic
from zentral.core.probes.views import BaseProbeView
from zentral.core.stores import frontend_store
from zentral.utils.text import str_to_ascii
from .conf import event_type_probes
from .forms import (MetaBusinessUnitSearchForm, MachineGroupSearchForm, MachineSearchForm,
                    MergeMBUForm, MBUAPIEnrollmentForm, AddMBUTagForm, AddMachineTagForm)
from .models import MetaBusinessUnit, MachineGroup, MachineSnapshot, MetaMachine, MetaBusinessUnitTag, MachineTag, Tag


class MachineListView(generic.TemplateView):
    template_name = "inventory/machine_list.html"

    def get_object(self, **kwargs):
        return None

    def get_list_qs(self, **kwargs):
        return MachineSnapshot.objects.current()

    def get_list_title(self, **kwargs):
        return ""

    def get_breadcrumbs(self, **kwargs):
        return []

    def get(self, request, *args, **kwargs):
        self.search_form = MachineSearchForm(request.GET)
        return super(MachineListView, self).get(request, *args, **kwargs)

    @staticmethod
    def _ms_dict_sorting_key(ms_list):
        key = None
        if not ms_list:
            return key
        ms = ms_list[0]
        key = str_to_ascii(ms.get_machine_str()).lower()
        return key

    def _get_filtered_qs(self, **kwargs):
        qs = self.get_list_qs(**kwargs)
        if self.search_form.is_valid():
            cleaned_data = self.search_form.cleaned_data
            serial_number = cleaned_data['serial_number']
            if serial_number:
                qs = qs.filter(machine__serial_number__icontains=serial_number)
            name = cleaned_data['name']
            if name:
                qs = qs.filter(system_info__computer_name__icontains=name)
            source = cleaned_data['source']
            if source:
                qs = qs.filter(source=source)
        return qs

    def get_context_data(self, **kwargs):
        context = super(MachineListView, self).get_context_data(**kwargs)
        self.object = self.get_object(**kwargs)
        context['object'] = self.object
        context['inventory'] = True
        # group by machine serial number
        ms_dict = {}
        for ms in self._get_filtered_qs(**kwargs).order_by('system_info__computer_name'):
            ms_dict.setdefault(ms.machine.serial_number, []).append(ms)
        # sorted
        context['object_list'] = [(l[0].machine.serial_number,
                                   l[0].get_machine_str(),
                                   l,
                                   MetaMachine(l[0].machine.serial_number, l).tags())
                                  for l in sorted(ms_dict.values(),
                                                  key=self._ms_dict_sorting_key)]
        context['object_list_title'] = self.get_list_title(**kwargs)
        context['search_form'] = self.search_form
        context['breadcrumbs'] = self.get_breadcrumbs(**kwargs)
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


class GroupsView(generic.TemplateView):
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

    def get_list_qs(self, **kwargs):
        return MachineSnapshot.objects.current().filter(groups__id=kwargs['group_id'])

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


class MBUView(generic.TemplateView):
    template_name = "inventory/mbu_list.html"

    def get(self, request, *args, **kwargs):
        self.search_form = MetaBusinessUnitSearchForm(request.GET)
        return super(MBUView, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(MBUView, self).get_context_data(**kwargs)
        context['inventory'] = True
        qs = MetaBusinessUnit.objects.all()
        if self.search_form.is_valid():
            name = self.search_form.cleaned_data['name']
            if name:
                qs = qs.filter(name__icontains=name)
            source = self.search_form.cleaned_data['source']
            if source:
                qs = qs.filter(businessunit__source=source)
        context['object_list'] = qs
        context['search_form'] = self.search_form
        l = []
        if self.search_form.is_valid() and len([i for i in self.search_form.cleaned_data.values() if i]):
            l.append((reverse('inventory:mbu'), 'Inventory business units'))
            l.append((None, "Search"))
        else:
            l.append((None, "Inventory business units"))
        context['breadcrumbs'] = l
        return context


class ReviewMBUMergeView(generic.TemplateView):
    template_name = "inventory/review_mbu_merge.html"

    def get_context_data(self, **kwargs):
        ctx = super(ReviewMBUMergeView, self).get_context_data(**kwargs)
        ctx['meta_business_units'] = MetaBusinessUnit.objects.filter(id__in=self.request.GET.getlist('mbu_id'))
        return ctx


class MergeMBUView(generic.FormView):
    template_name = "inventory/merge_mbu.html"
    form_class = MergeMBUForm

    def form_valid(self, form):
        self.dest_mbu = form.merge()
        return super(MergeMBUView, self).form_valid(form)

    def get_success_url(self):
        return reverse('inventory:mbu_machines', args=(self.dest_mbu.id,))


class CreateMBUView(generic.CreateView):
    template_name = "inventory/edit_mbu.html"
    model = MetaBusinessUnit
    fields = ('name',)


class UpdateMBUView(generic.UpdateView):
    template_name = "inventory/edit_mbu.html"
    model = MetaBusinessUnit
    fields = ('name',)


class MBUTagsView(generic.FormView):
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


class RemoveMBUTagView(generic.View):
    def post(self, request, *args, **kwargs):
        MetaBusinessUnitTag.objects.filter(tag__id=kwargs['tag_id'],
                                           meta_business_unit__id=kwargs['pk']).delete()
        return HttpResponseRedirect(reverse('inventory:mbu_tags', args=(kwargs['pk'],)))


class MBUAPIEnrollmentView(generic.UpdateView):
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

    def get_list_qs(self, **kwargs):
        return MachineSnapshot.objects.current().filter(business_unit__meta_business_unit=self.object)

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


class MachineView(generic.TemplateView):
    template_name = "inventory/machine_detail.html"

    def get_context_data(self, **kwargs):
        context = super(MachineView, self).get_context_data(**kwargs)
        context['inventory'] = True
        context['machine'] = MetaMachine(context['serial_number'])
        return context


class MachineEventSet(object):
    def __init__(self, machine_serial_number, event_type=None):
        self.machine_serial_number = machine_serial_number
        self.event_type = event_type
        self.store = frontend_store
        self._count = None

    def count(self):
        if self._count is None:
            self._count = self.store.count(self.machine_serial_number, self.event_type)
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
        return self.store.fetch(self.machine_serial_number, start, stop - start, self.event_type)


class MachineEventsView(generic.ListView):
    template_name = "inventory/machine_events.html"
    paginate_by = 10

    def get_context_data(self, **kwargs):
        context = super(MachineEventsView, self).get_context_data(**kwargs)
        for ms in self.ms_list:
            context['serial_number'] = ms.machine.serial_number
            if ms.system_info and ms.system_info.computer_name:
                context['computer_name'] = ms.system_info.computer_name
                break

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
        for event_type, count in frontend_store.event_types_with_usage(
                context['serial_number']).items():
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
        serial_number = self.kwargs['serial_number']
        self.ms_list = list(MachineSnapshot.objects.current().filter(machine__serial_number=serial_number))
        et = self.request.GET.get('event_type')
        return MachineEventSet(serial_number, et)


class MachineTagsView(generic.FormView):
    template_name = "inventory/machine_tags.html"
    form_class = AddMachineTagForm

    def dispatch(self, request, *args, **kwargs):
        self.msn = kwargs['serial_number']
        return super(MachineTagsView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(MachineTagsView, self).get_context_data(**kwargs)
        context['inventory'] = True
        context['machine'] = MetaMachine(self.msn)
        context['tags'] = context['machine'].tags_with_types()
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


class RemoveMachineTagView(generic.View):
    def post(self, request, *args, **kwargs):
        MachineTag.objects.filter(tag__id=kwargs['tag_id'],
                                  serial_number=kwargs['serial_number']).delete()
        return HttpResponseRedirect(reverse('inventory:machine_tags', args=(kwargs['serial_number'],)))


class ProbesView(generic.TemplateView):
    template_name = "inventory/probes.html"

    def get_context_data(self, **kwargs):
        context = super(ProbesView, self).get_context_data(**kwargs)
        context['inventory'] = True
        context['event_type_probes'] = event_type_probes
        return context


class ProbeView(BaseProbeView):
    section = "inventory"


class TagsView(generic.ListView):
    model = Tag

    def get_context_data(self, **kwargs):
        ctx = super(TagsView, self).get_context_data(**kwargs)
        ctx['inventory'] = True
        return ctx


class UpdateTagView(generic.UpdateView):
    template_name = "inventory/edit_tag.html"
    model = Tag
    fields = ('name', 'color')
    color_presets = {
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

    def get_context_data(self, **kwargs):
        ctx = super(UpdateTagView, self).get_context_data(**kwargs)
        ctx['color_presets'] = self.color_presets
        return ctx

    def get_success_url(self):
        return reverse('inventory:tags')
