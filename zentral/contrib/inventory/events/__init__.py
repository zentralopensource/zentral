from enum import Enum
import logging
import uuid
from zentral.core.events import event_cls_from_type, register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest

logger = logging.getLogger('zentral.contrib.inventory.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "machine"}


# Inventory update events


class InventoryHeartbeat(BaseEvent):
    event_type = 'inventory_heartbeat'
    namespace = "inventory"
    tags = ['heartbeat', 'machine']


register_event_type(InventoryHeartbeat)


class AddMachine(BaseEvent):
    event_type = 'add_machine'
    namespace = "inventory"
    tags = ['machine']


register_event_type(AddMachine)


for attr in ('link',
             'business_unit',
             'group',
             'os_version',
             'system_info',
             'disk',
             'network_interface',
             'android_app',
             'deb_package',
             'ios_app',
             'osx_app_instance',
             'program_instance',
             'profile',
             'teamviewer',
             'puppet_node',
             'principal_user',
             'certificate',
             'extra_facts',
             'ec2_instance_metadata',
             'ec2_instance_tag',):
    for action in ("add", "remove"):
        event_type = f"{action}_machine_{attr}"
        event_class_name = "".join(s.title() for s in event_type.split('_'))
        event_class = type(
            event_class_name,
            (BaseEvent,),
            {'event_type': event_type,
             'namespace': 'inventory',
             'tags': ['machine', 'machine_update', f'machine_{action}_update']}
        )
        register_event_type(event_class)


def iter_inventory_events(msn, events):
    event_uuid = uuid.uuid4()
    for index, (event_type, created_at, data) in enumerate(events):
        event_cls = event_cls_from_type(event_type)
        metadata = EventMetadata(machine_serial_number=msn,
                                 uuid=event_uuid, index=index,
                                 created_at=created_at)
        yield event_cls(metadata, data)


# enrollment secret


class EnrollmentSecretVerificationEvent(BaseEvent):
    event_type = 'enrollment_secret_verification'


register_event_type(EnrollmentSecretVerificationEvent)


def post_enrollment_secret_verification_failure(model,
                                                user_agent, public_ip_address, serial_number,
                                                err_msg, enrollment_secret):
    event_cls = EnrollmentSecretVerificationEvent
    metadata = EventMetadata(machine_serial_number=serial_number,
                             request=EventRequest(user_agent, public_ip_address))
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
    metadata = EventMetadata(machine_serial_number=request.serial_number,
                             request=EventRequest(request.user_agent, request.public_ip_address))
    payload = {"status": "success",
               "type": model}
    payload.update(obj.serialize_for_event())
    event = event_cls(metadata, payload)
    event.post()


# compliance checks


class JMESPathCheckBaseEvent(BaseEvent):
    namespace = 'compliance_check'
    tags = ['compliance_check', 'inventory_jmespath_check']

    @classmethod
    def build_from_request_and_object(cls, request, jmespath_check):
        payload = jmespath_check.compliance_check.serialize_for_event()
        payload["inventory_jmespath_check"] = jmespath_check.serialize_for_event()
        return cls(EventMetadata(request=EventRequest.build_from_request(request)), payload)

    def get_linked_objects_keys(self):
        keys = {}
        pk = self.payload.get("pk")
        if pk:
            keys["compliance_check"] = [(pk,)]
        jmespath_check_pk = self.payload.get("inventory_jmespath_check", {}).get("pk")
        if jmespath_check_pk:
            keys["inventory_jmespath_check"] = [(jmespath_check_pk,)]
        return keys


class JMESPathCheckCreated(JMESPathCheckBaseEvent):
    event_type = 'inventory_jmespath_check_created'


register_event_type(JMESPathCheckCreated)


class JMESPathCheckUpdated(JMESPathCheckBaseEvent):
    event_type = 'inventory_jmespath_check_updated'


register_event_type(JMESPathCheckUpdated)


class JMESPathCheckDeleted(JMESPathCheckBaseEvent):
    event_type = 'inventory_jmespath_check_deleted'


register_event_type(JMESPathCheckDeleted)


class JMESPathCheckStatusUpdated(BaseEvent):
    event_type = 'inventory_jmespath_check_status_updated'
    namespace = 'compliance_check'
    tags = ['compliance_check', 'inventory_jmespath_check', 'compliance_check_status']

    @classmethod
    def build_from_object_serial_number_and_statuses(
        cls,
        jmespath_check,
        serial_number,
        status, status_time,
        previous_status
    ):
        payload = jmespath_check.compliance_check.serialize_for_event()
        payload["inventory_jmespath_check"] = jmespath_check.serialize_for_event()
        payload["status"] = status.name
        if previous_status is not None:
            payload["previous_status"] = previous_status.name
        return cls(EventMetadata(machine_serial_number=serial_number, created_at=status_time), payload)

    def get_linked_objects_keys(self):
        keys = {}
        pk = self.payload.get("pk")
        if pk:
            keys["compliance_check"] = [(pk,)]
        jmespath_check_pk = self.payload.get("inventory_jmespath_check", {}).get("pk")
        if jmespath_check_pk:
            keys["inventory_jmespath_check"] = [(jmespath_check_pk,)]
        return keys


register_event_type(JMESPathCheckStatusUpdated)


# machine tags


class MachineTagEvent(BaseEvent):
    class Action(Enum):
        ADDED = "added"
        REMOVED = "removed"

    event_type = 'machine_tag'
    tags = ['machine']


register_event_type(MachineTagEvent)


# cleanup


class BaseInventoryCleanupEvent(BaseEvent):
    namespace = "inventory"
    tags = ["inventory", "inventory_cleanup", "zentral"]


class InventoryCleanupStarted(BaseInventoryCleanupEvent):
    event_type = "inventory_cleanup_started"


register_event_type(InventoryCleanupStarted)


def post_cleanup_started_event(payload, serialized_event_request):
    request = EventRequest.deserialize(serialized_event_request)
    metadata = EventMetadata(request=request)
    event = InventoryCleanupStarted(metadata, {"cleanup": payload})
    event.post()


class InventoryCleanupFinished(BaseInventoryCleanupEvent):
    event_type = "inventory_cleanup_finished"


register_event_type(InventoryCleanupFinished)


def post_cleanup_finished_event(payload, serialized_event_request):
    request = EventRequest.deserialize(serialized_event_request)
    metadata = EventMetadata(request=request)
    event = InventoryCleanupFinished(metadata, {"cleanup": payload})
    event.post()
