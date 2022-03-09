import logging
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest
from zentral.core.queues import queues


logger = logging.getLogger('zentral.contrib.wsone.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "wsone"}


# webhook events


class BaseWSOneEvent(BaseEvent):
    namespace = "wsone_event"
    tags = ["wsone", "wsone_event"]

    def get_linked_objects_keys(self):
        keys = {}
        observer = self.metadata.observer
        if observer and observer.content_type == "wsone.instance" and observer.pk:
            keys["wsone_instance"] = [(observer.pk,)]
        return keys


# device compliance/compromised status


class WSOneComplianceStatusChanged(BaseWSOneEvent):
    event_type = "wsone_compliance_status_changed"


register_event_type(WSOneComplianceStatusChanged)


class WSOneCompromisedStatusChanged(BaseWSOneEvent):
    event_type = "wsone_compromised_status_changed"


register_event_type(WSOneCompromisedStatusChanged)


# device enrollment


# type = "Break MDM Confirmed"
class WSOneBreakMDMConfirmed(BaseWSOneEvent):
    event_type = "wsone_break_mdm_confirmed"


register_event_type(WSOneBreakMDMConfirmed)


# type = "Enrollment Complete"
class WSOneEnrollmentComplete(BaseWSOneEvent):
    event_type = "wsone_enrollment_complete"


register_event_type(WSOneEnrollmentComplete)


# type = "MDM Enrollment Complete"
class WSOneMDMEnrollmentComplete(BaseWSOneEvent):
    event_type = "wsone_mdm_enrollment_complete"


register_event_type(WSOneMDMEnrollmentComplete)


# device attribute changes


# type = "Device MCC"
class WSOneMCCChanged(BaseWSOneEvent):
    event_type = "wsone_mcc_changed"


register_event_type(WSOneMCCChanged)


# type = "Device Organization Group Changed"
class WSOneOrganizationGroupChanged(BaseWSOneEvent):
    event_type = "wsone_organization_group_changed"


register_event_type(WSOneOrganizationGroupChanged)


# type = "Device Operating System Changed"
class WSOneOSChanged(BaseWSOneEvent):
    event_type = "wsone_os_changed"


register_event_type(WSOneOSChanged)


def post_webhook_event(instance, user_agent, ip, wsone_event):
    raw_event = {"request": {"user_agent": user_agent,
                             "ip": ip},
                 "observer": instance.observer_dict(),
                 "wsone_instance": {"pk": instance.pk,
                                    "version": instance.version},
                 "wsone_event": wsone_event}
    queues.post_raw_event("wsone_events", raw_event)


# audit events


class BaseWSOneAuditEvent(BaseEvent):
    namespace = "wsone"
    tags = ["wsone", "zentral"]

    def get_linked_objects_keys(self):
        keys = {}
        instance_pk = self.payload.get("instance", {}).get("pk")
        if instance_pk:
            keys["wsone_instance"] = [(instance_pk,)]
        return keys


class WSOneInstanceCreated(BaseWSOneAuditEvent):
    event_type = "wsone_instance_created"


register_event_type(WSOneInstanceCreated)


def post_instance_created_event(instance, request):
    metadata = EventMetadata(request=EventRequest.build_from_request(request))
    event = WSOneInstanceCreated(metadata, {"instance": instance.serialize_for_event()})
    event.post()


class WSOneInstanceUpdated(BaseWSOneAuditEvent):
    event_type = "wsone_instance_updated"


register_event_type(WSOneInstanceUpdated)


def post_instance_updated_event(instance, request):
    metadata = EventMetadata(request=EventRequest.build_from_request(request))
    event = WSOneInstanceUpdated(metadata, {"instance": instance.serialize_for_event()})
    event.post()


class WSOneInstanceDeleted(BaseWSOneAuditEvent):
    event_type = "wsone_instance_deleted"


register_event_type(WSOneInstanceDeleted)


def post_instance_deleted_event(serialized_instance, request):
    metadata = EventMetadata(request=EventRequest.build_from_request(request))
    event = WSOneInstanceDeleted(metadata, {"instance": serialized_instance})
    event.post()


class WSOneInstanceSyncStarted(BaseWSOneAuditEvent):
    event_type = "wsone_instance_sync_started"


register_event_type(WSOneInstanceSyncStarted)


def post_sync_started_event(instance, serialized_event_request):
    request = None
    if serialized_event_request:
        request = EventRequest.deserialize(serialized_event_request)
    metadata = EventMetadata(request=request)
    event = WSOneInstanceSyncStarted(metadata, {"instance": instance.serialize_for_event()})
    event.post()


class WSOneInstanceSyncFinished(BaseWSOneAuditEvent):
    event_type = "wsone_instance_sync_finished"


register_event_type(WSOneInstanceSyncFinished)


def post_sync_finished_event(instance, serialized_event_request, result):
    request = None
    if serialized_event_request:
        request = EventRequest.deserialize(serialized_event_request)
    metadata = EventMetadata(request=request)
    event = WSOneInstanceSyncFinished(metadata, {"instance": instance.serialize_for_event(), "sync": result})
    event.post()
