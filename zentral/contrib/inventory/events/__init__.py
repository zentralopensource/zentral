import logging
import uuid
from enum import Enum

from zentral.core.events import event_cls_from_type, register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest, linked_objects_key
from zentral.core.queues import queues
from zentral.contrib.inventory.models import MetaBusinessUnit

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


class ArchiveMachine(BaseEvent):
    event_type = 'archive_machine'
    namespace = "inventory"
    tags = ['machine']


register_event_type(ArchiveMachine)


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


class EnrollmentInfoRequestEvent(BaseEvent):
    event_type = 'enrollment_info_request'
    tags = ['inventory']


register_event_type(EnrollmentInfoRequestEvent)


def post_enrollment_info_request_event(model, user_agent, ip, payload, machine_serial_number=None):
    # `model` mirrors the EnrollmentSecret related_name (e.g. "munki_enrollment");
    # written to payload["type"] for symmetry with EnrollmentSecretVerificationEvent.
    enriched = {"type": model, **payload}
    EnrollmentInfoRequestEvent.post_machine_request_payloads(machine_serial_number, user_agent, ip, [enriched])


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


def post_machine_snapshot_raw_event(ms_tree):
    queues.post_raw_event("inventory_machine_snapshot", {"ms_tree": ms_tree})


# The read of the enrollment secrets that one response holds: in the API, in a download, or on a page. The
# request of the event names the reader.


class EnrollmentSecretViewedEvent(BaseEvent):
    event_type = "enrollment_secret_viewed"
    tags = ["zentral", "enrollment_secret"]


register_event_type(EnrollmentSecretViewedEvent)


def post_enrollment_secret_viewed_event(request, enrollments, secret_field, where):
    """One event for the secrets that one response holds."""
    if not enrollments:
        return
    payload_enrollments = []
    # linked, so that the events of the enrollments and of their business units show the read
    enrollment_keys = {}
    mbu_pks = {}
    for enrollment in enrollments:
        payload_enrollment = {
            "module": enrollment._meta.app_label,
            "model": enrollment._meta.model_name,
            "pk": enrollment.pk,
        }
        enrollment_keys.setdefault(linked_objects_key(enrollment), {})[(enrollment.pk,)] = None
        secret = getattr(enrollment, secret_field)
        if secret.meta_business_unit_id:
            payload_enrollment["meta_business_unit"] = {"pk": secret.meta_business_unit_id}
            mbu_pks[(secret.meta_business_unit_id,)] = None
        payload_enrollments.append(payload_enrollment)
    objects = {key: list(pks) for key, pks in enrollment_keys.items()}
    if mbu_pks:
        objects[linked_objects_key(MetaBusinessUnit)] = list(mbu_pks)
    EnrollmentSecretViewedEvent(
        EventMetadata(request=EventRequest.build_from_request(request), objects=objects),
        {"enrollments": payload_enrollments, "where": where},
    ).post()
