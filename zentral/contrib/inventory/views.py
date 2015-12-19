from django.views import generic
from zentral.contrib.osquery.models import Node
from zentral.core.stores import frontend_store
from . import inventory


class IndexView(generic.ListView):
    template_name = "inventory/machine_list.html"

    def get_queryset(self):
        return inventory.machines().order_by('system_info__computer_name')

    def get_context_data(self, **kwargs):
        context = super(IndexView, self).get_context_data(**kwargs)
        context['inventory'] = True
        return context


class MachineView(generic.TemplateView):
    template_name = "inventory/machine_detail.html"

    def get_context_data(self, **kwargs):
        context = super(MachineView, self).get_context_data(**kwargs)
        ms = inventory.machine(context['serial_number'])
        context['inventory'] = True
        context['machine_snapshot'] = ms
        context['business_unit'] = ms.business_unit
        context['machine'] = ms.machine
        context['system_info'] = ms.system_info
        context['os_version'] = ms.os_version
        context['links'] = []
        context['nodes'] = Node.objects.filter(enroll_secret__icontains=context['serial_number'])
        try:
            from zentral.contrib.munki.models import MunkiState
            context['munki_state'] = MunkiState.objects.get(machine_serial_number=context['serial_number'])
        except:
            pass
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
        context['inventory'] = True
        context['machine_snapshot'] = self.machine_snapshot
        context['business_unit'] = self.machine_snapshot.business_unit
        context['machine'] = self.machine_snapshot.machine
        context['system_info'] = self.machine_snapshot.system_info
        context['os_version'] = self.machine_snapshot.os_version
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
        request_event_type = self.request.GET.get('event_type')
        for event_type, count in frontend_store.event_types_with_usage(
                self.machine_snapshot.machine.serial_number).items():
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
        self.machine_snapshot = inventory.machine(self.kwargs['serial_number'])
        et = self.request.GET.get('event_type')
        return MachineEventSet(self.machine_snapshot.machine.serial_number, et)
