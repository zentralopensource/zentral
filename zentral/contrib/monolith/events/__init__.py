import logging
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest, register_event_type

logger = logging.getLogger('zentral.contrib.monolith.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "monolith"}


class MonolithEnrollmentEvent(BaseEvent):
    event_type = "monolith_enrollment"
    tags = ["monolith"]


register_event_type(MonolithEnrollmentEvent)


class MonolithMunkiRequestEvent(BaseEvent):
    event_type = "monolith_munki_request"
    tags = ["monolith", "heartbeat"]
    heartbeat_timeout = 2 * 3600


register_event_type(MonolithMunkiRequestEvent)


class MonolithSyncCatalogsRequestEvent(BaseEvent):
    event_type = "monolith_sync_catalogs_request"
    tags = ["monolith"]


register_event_type(MonolithSyncCatalogsRequestEvent)


class MonolithUpdateCacheServerRequestEvent(BaseEvent):
    event_type = "monolith_update_cache_server_request"
    tags = ["monolith"]


register_event_type(MonolithUpdateCacheServerRequestEvent)


class MonolithRepositoryUpdateEvent(BaseEvent):
    event_type = "monolith_repository_update"
    tags = ["monolith"]
    payload_aggregations = [
        ("action", {"type": "terms", "bucket_number": 4, "label": "Decisions"}),
    ]


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


def post_monolith_cache_server_update_request(user_agent, ip, cache_server=None, errors=None):
    event_class = MonolithUpdateCacheServerRequestEvent
    if user_agent or ip:
        request = EventRequest(user_agent, ip)
    else:
        request = None
    metadata = EventMetadata(event_class.event_type,
                             request=request,
                             tags=event_class.tags)
    if cache_server:
        payload = cache_server.serialize()
        payload["status"] = 0
    else:
        # flatten errors
        payload = {"errors": {attr: ", ".join(err) for attr, err in errors.items()}}
        payload["status"] = 1
    event = event_class(metadata, payload)
    event.post()


def post_monolith_repository_updates(repository, payloads, request=None):
    event_class = MonolithRepositoryUpdateEvent
    repository_serialized_info = repository.serialize_for_event()
    if request:
        request = EventRequest.build_from_request(request)
    for index, payload in enumerate(payloads):
        metadata = EventMetadata(event_class.event_type,
                                 index=index,
                                 request=request,
                                 tags=event_class.tags)
        payload.update({"repository": repository_serialized_info})
        event = event_class(metadata, payload)
        event.post()


def post_monolith_enrollment_event(msn, user_agent, ip, data):
    MonolithEnrollmentEvent.post_machine_request_payloads(msn, user_agent, ip, [data])
