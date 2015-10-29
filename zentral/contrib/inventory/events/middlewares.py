from django.utils.functional import SimpleLazyObject
from zentral.contrib.inventory import inventory


def get_machine(event):
    if not hasattr(event, '_cached_machine'):
        msn = event.metadata.machine_serial_number
        event._cached_machine = inventory.machine(msn)
    return event._cached_machine


class MachineMiddleware(object):
    """Add machine attribute to the event with the machine info."""

    def process_event(self, event):
        event.machine = SimpleLazyObject(lambda: get_machine(event))
