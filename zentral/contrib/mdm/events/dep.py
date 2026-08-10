import logging

from zentral.core.events import register_event_type
from zentral.core.events.base import AuditEvent

logger = logging.getLogger('zentral.contrib.mdm.events.dep')


# Automated Device Enrollment device changes


ORIGIN_SYNC = "sync"
ORIGIN_DEFAULT_ENROLLMENT_ASSIGNMENT = "default_enrollment_assignment"


class DEPDeviceChangeEvent(AuditEvent):
    """A change Apple made, not one an operator asked for.

    The payload is an audit event's, so that a DEP device has one history whichever end changed it,
    but the event type is not: these are machine generated, one per device of a virtual server, and
    they would bury the operator actions in the audit trail. The zentral tag is dropped with it.
    """
    event_type = "dep_device_change"
    tags = ["mdm", "dep"]


register_event_type(DEPDeviceChangeEvent)


def build_dep_device_change_event(
    dep_device, action, prev_value=None, origin=ORIGIN_SYNC,
    event_uuid=None, event_index=None, event_request=None
):
    event = DEPDeviceChangeEvent.build(
        dep_device, action,
        prev_value=prev_value,
        event_uuid=event_uuid,
        event_index=event_index,
        event_request=event_request,
        machine_serial_number=dep_device.serial_number,
    )
    event.payload["origin"] = origin
    return event
