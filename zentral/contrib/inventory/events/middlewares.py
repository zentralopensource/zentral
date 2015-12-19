from django.utils.functional import SimpleLazyObject
from zentral.contrib.inventory.models import MachineSnapshot


def get_machine(event):
    if not hasattr(event, '_cached_machine'):
        msn = event.metadata.machine_serial_number
        ms_d = {}
        for ms in MachineSnapshot.objects.current().filter(machine__serial_number=msn):
            ms_d[ms.source] = ms.serialize()
        event._cached_machine = ms_d
    return event._cached_machine


class MachineMiddleware(object):
    """Add machine attribute to the event with the machine info."""

    def process_event(self, event):
        event.machine = SimpleLazyObject(lambda: get_machine(event))
