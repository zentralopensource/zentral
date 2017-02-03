import logging
from zentral.core.events import event_cls_from_type, register_event_type
from zentral.core.events.base import BaseEvent

logger = logging.getLogger('zentral.contrib.nagios.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "nagios"}


class NagiosEvent(BaseEvent):
    tags = ["nagios"]


class NagiosHostEvent(NagiosEvent):
    event_type = "nagios_host_event"


register_event_type(NagiosHostEvent)


class NagiosServiceEvent(NagiosEvent):
    event_type = "nagios_service_event"


register_event_type(NagiosServiceEvent)


def post_nagios_event(nagios_instance, user_agent, ip, data):
    event_type = data.pop("event_type", None)
    if not event_type:
        logger.warning("Missing event_type in nagios event payload")
        return
    elif event_type not in ['nagios_host_event', 'nagios_service_event']:
        logger.warning("Wrong event_type %s in nagios event payload", event_type)
        return
    data["nagios_instance"] = {"id": nagios_instance.id,
                               "url": nagios_instance.url}
    event_cls = event_cls_from_type(event_type)
    event_cls.post_machine_request_payloads(None, user_agent, ip, [data])
