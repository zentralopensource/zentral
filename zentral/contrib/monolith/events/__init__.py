import logging
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest, register_event_type

logger = logging.getLogger('zentral.contrib.monolith.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "monolith"}


class MonolithMunkiRequestEvent(BaseEvent):
    event_type = "monolith_munki_request"
    tags = ["monolith", "heartbeat"]


register_event_type(MonolithMunkiRequestEvent)


class MonolithSyncCatalogsRequestEvent(BaseEvent):
    event_type = "monolith_sync_catalogs_request"
    tags = ["monolith"]


register_event_type(MonolithSyncCatalogsRequestEvent)


class MonolithRepositoryUpdateEvent(BaseEvent):
    event_type = "monolith_repository_update"
    tags = ["monolith"]


register_event_type(MonolithRepositoryUpdateEvent)


# Utility functions


def post_monolith_munki_request(msn, user_agent, ip, **payload):
    MonolithMunkiRequestEvent.post_machine_request_payloads(msn, user_agent, ip, [payload])


def post_monolith_sync_catalogs_request(user_agent, ip):
    event_class = MonolithSyncCatalogsRequestEvent
    if user_agent or ip:
        request = EventRequest(user_agent, ip)
    else:
        request = None
    metadata = EventMetadata(event_class.event_type,
                             request=request,
                             tags=event_class.tags)
    event = event_class(metadata, {})
    event.post()


def post_monolith_repository_updates(repository, payloads):
    event_class = MonolithRepositoryUpdateEvent
    repository_serialized_info = repository.serialize_for_event()
    for index, payload in enumerate(payloads):
        metadata = EventMetadata(event_class.event_type,
                                 index=index,
                                 tags=event_class.tags)
        payload.update({"repository": repository_serialized_info})
        event = event_class(metadata, payload)
        event.post()
