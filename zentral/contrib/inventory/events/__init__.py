import logging
from zentral.core.events import event_cls_from_type, register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest

logger = logging.getLogger('zentral.contrib.inventory.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "inventory_update"}


class InventoryMachineAdded(BaseEvent):
    event_type = 'inventory_machine_added'


register_event_type(InventoryMachineAdded)


class InventoryHeartbeat(BaseEvent):
    event_type = 'inventory_heartbeat'
    tags = ['heartbeat']


register_event_type(InventoryHeartbeat)


class EnrollmentSecretVerificationEvent(BaseEvent):
    event_type = 'enrollment_secret_verification'


register_event_type(EnrollmentSecretVerificationEvent)


# Inventory update events
for attr in ('reference',
             'machine',
             'link',
             'business_unit',
             'group',
             'os_version',
             'system_info',
             'network_interface',
             'osx_app_instance',
             'deb_package',
             'teamviewer',
             'puppet_node',
             'principal_user',
             'certificate'):
    event_type = 'inventory_{}_update'.format(attr)
    event_class_name = "".join(s.title() for s in event_type.split('_'))
    event_class = type(event_class_name, (BaseEvent,), {'event_type': event_type, 'tags': ['inventory_update']})
    register_event_type(event_class)


def post_inventory_events(msn, events):
    for index, (event_type, created_at, data) in enumerate(events):
        event_cls = event_cls_from_type(event_type)
        metadata = EventMetadata(event_cls.event_type,
                                 machine_serial_number=msn,
                                 index=index,
                                 created_at=created_at,
                                 tags=event_cls.tags)
        event = event_cls(metadata, data)
        event.post()


def post_enrollment_secret_verification_failure(model,
                                                user_agent, public_ip_address, serial_number,
                                                err_msg, enrollment_secret):
    event_cls = EnrollmentSecretVerificationEvent
    metadata = EventMetadata(event_cls.event_type,
                             machine_serial_number=serial_number,
                             request=EventRequest(user_agent, public_ip_address),
                             tags=event_cls.tags)
    payload = {"status": "failure",
               "reason": err_msg,
               "type": model}
    if enrollment_secret:
        obj = getattr(enrollment_secret, model)
        payload.update(obj.serialize_for_event())
    event = event_cls(metadata, payload)
    event.post()


def post_enrollment_secret_verification_success(request, model):
    obj = getattr(request.enrollment_secret, model)
    event_cls = EnrollmentSecretVerificationEvent
    metadata = EventMetadata(event_cls.event_type,
                             machine_serial_number=request.serial_number,
                             request=EventRequest(request.user_agent, request.public_ip_address),
                             tags=event_cls.tags)
    payload = {"status": "success",
               "type": model}
    payload.update(obj.serialize_for_event())
    event = event_cls(metadata, payload)
    event.post()
