import logging
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest
from zentral.core.queues import queues


logger = logging.getLogger('zentral.contrib.puppet.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "puppet"}


# report event


class PuppetReportEvent(BaseEvent):
    event_type = "puppet_report"
    tags = ["puppet"]

    def get_linked_objects_keys(self):
        keys = {}
        observer = self.metadata.observer
        if observer and observer.content_type == "puppet.instance" and observer.pk:
            keys["puppet_instance"] = [(observer.pk,)]
        return keys


register_event_type(PuppetReportEvent)


def post_puppet_report(pk, version, observer_dict, user_agent, ip, report):
    raw_event = {"request": {"user_agent": user_agent,
                             "ip": ip},
                 "observer": observer_dict,
                 "puppet_instance": {"pk": pk,
                                     "version": version},
                 "puppet_report": report}
    queues.post_raw_event("puppet_reports", raw_event)


# audit events


class BasePuppetAuditEvent(BaseEvent):
    namespace = "puppet"
    tags = ["puppet", "zentral"]

    def get_linked_objects_keys(self):
        keys = {}
        instance_pk = self.payload.get("instance", {}).get("pk")
        if instance_pk:
            keys["puppet_instance"] = [(instance_pk,)]
        return keys


class PuppetInstanceCreated(BasePuppetAuditEvent):
    event_type = "puppet_instance_created"


register_event_type(PuppetInstanceCreated)


def post_instance_created_event(instance, request):
    metadata = EventMetadata(request=EventRequest.build_from_request(request))
    event = PuppetInstanceCreated(metadata, {"instance": instance.serialize_for_event()})
    event.post()


class PuppetInstanceUpdated(BasePuppetAuditEvent):
    event_type = "puppet_instance_updated"


register_event_type(PuppetInstanceUpdated)


def post_instance_updated_event(instance, request):
    metadata = EventMetadata(request=EventRequest.build_from_request(request))
    event = PuppetInstanceUpdated(metadata, {"instance": instance.serialize_for_event()})
    event.post()


class PuppetInstanceDeleted(BasePuppetAuditEvent):
    event_type = "puppet_instance_deleted"


register_event_type(PuppetInstanceDeleted)


def post_instance_deleted_event(serialized_instance, request):
    metadata = EventMetadata(request=EventRequest.build_from_request(request))
    event = PuppetInstanceDeleted(metadata, {"instance": serialized_instance})
    event.post()
