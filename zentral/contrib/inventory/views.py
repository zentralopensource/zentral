from django.views import generic
from zentral.contrib.osquery.models import Node
from zentral.core.stores import frontend_store
from . import inventory


class IndexView(generic.ListView):
    template_name = "inventory/machine_list.html"

    def get_queryset(self):
        machines = inventory.machines()
        machines.sort(key=lambda d: d['name'].upper())
        return machines

    def get_context_data(self, **kwargs):
        context = super(IndexView, self).get_context_data(**kwargs)
        context['inventory'] = True
        return context


class MachineView(generic.TemplateView):
    template_name = "inventory/machine_detail.html"

    def get_context_data(self, **kwargs):
        context = super(MachineView, self).get_context_data(**kwargs)
        md = inventory.machine(context['serial_number'])
        context['inventory'] = True
        context['machine'] = md
        context['links'] = md['_links']
        context['nodes'] = Node.objects.filter(enroll_secret__icontains=context['serial_number'])
        return context


class MachineEventSet(object):
    def __init__(self, machine_serial_number, event_type=None):
        self.machine_serial_number = machine_serial_number
        self.event_type = event_type
        self.store = frontend_store

    def count(self):
        return self.store.count(self.machine_serial_number, self.event_type)

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
        context['machine'] = self.machine
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
        for event_type, count in frontend_store.event_types_with_usage(self.machine['serial_number']).items():
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
        self.machine = inventory.machine(self.kwargs['serial_number'])
        et = self.request.GET.get('event_type')
        return MachineEventSet(self.machine['serial_number'], et)
