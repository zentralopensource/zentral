import logging
from django.core.urlresolvers import reverse
from django.utils.functional import SimpleLazyObject
from zentral.conf import settings
from zentral.contrib.inventory.models import MachineSnapshot

logger = logging.getLogger('zentral.contrib.inventory.events.middlewares')


def get_machine(event):
    if not hasattr(event, '_cached_machine'):
        msn = event.metadata.machine_serial_number
        event._cached_machine = {}
        for ms in MachineSnapshot.objects.current().filter(machine__serial_number=msn):
            event._cached_machine[ms.source] = ms
    return event._cached_machine


def get_machine_url(event):
    if event.metadata.machine_serial_number:
        try:
            tls_hostname = settings['api']['tls_hostname']
        except KeyError:
            logger.warning("Missing api.tls_hostname configuration key")
        else:
            return "{}{}".format(tls_hostname.rstrip('/'),
                                 reverse('inventory:machine',
                                         args=(event.metadata.machine_serial_number,)))


class MachineMiddleware(object):
    """Add machine attribute to the event with the machine info."""

    def process_event(self, event):
        event.machine = SimpleLazyObject(lambda: get_machine(event))
        event.machine_url = SimpleLazyObject(lambda: get_machine_url(event))
