import logging
from zentral.contrib.inventory.models import MachineSnapshot
from zentral.contrib.puppet.models import Instance
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest
from zentral.core.queues import queues


logger = logging.getLogger('zentral.contrib.puppet.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "puppet"}


# report event


class PuppetReportEvent(BaseEvent):
    event_type = "puppet_report"
    tags = ["puppet", "heartbeat"]

    def get_linked_objects_keys(self):
        keys = {}
        observer = self.metadata.observer
        if observer and observer.content_type == "puppet.instance" and observer.pk:
            keys["puppet_instance"] = [(observer.pk,)]
        return keys

    @classmethod
    def get_machine_heartbeat_timeout(cls, serial_number):
        ms = MachineSnapshot.objects.select_related("source").filter(serial_number=serial_number,
                                                                     source__module="zentral.contrib.puppet",
                                                                     source__name="puppet").order_by("-id").first()
        if not ms:
            logger.warning("No Puppet machine snapshot found for serial number %s", serial_number)
            return
        try:
            instance = Instance.objects.get(url=ms.source.config["url"])
        except KeyError:
            logger.warning("Puppet source without URL")
        except Instance.DoesNotExist:
            logger.warning("No Puppet instance found for serial number %s", serial_number)
        else:
            return instance.report_heartbeat_timeout


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
