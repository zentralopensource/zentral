import logging
import uuid
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


def post_monolith_sync_catalogs_request(request):
    event_class = MonolithSyncCatalogsRequestEvent
    event_request = EventRequest.build_from_request(request)
    metadata = EventMetadata(request=event_request)
    event = event_class(metadata, {})
    event.post()


def post_monolith_cache_server_update_request(request, cache_server=None, errors=None):
    event_class = MonolithUpdateCacheServerRequestEvent
    event_request = EventRequest.build_from_request(request)
    metadata = EventMetadata(request=event_request)
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
    event_uuid = uuid.uuid4()
    for index, payload in enumerate(payloads):
        metadata = EventMetadata(uuid=event_uuid, index=index,
                                 request=request)
        payload.update({"repository": repository_serialized_info})
        event = event_class(metadata, payload)
        event.post()


def post_monolith_enrollment_event(msn, user_agent, ip, data):
    MonolithEnrollmentEvent.post_machine_request_payloads(msn, user_agent, ip, [data])
