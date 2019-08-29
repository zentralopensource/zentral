import logging
from dateutil import parser
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata, EventObserver, EventRequest, EventRequestGeo


logger = logging.getLogger('zentral.contrib.okta.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "okta"}


class OktaUserSessionStart(BaseEvent):
    event_type = "okta_user_session_start"
    tags = ["okta"]


register_event_type(OktaUserSessionStart)


class OktaUserSessionEnd(BaseEvent):
    event_type = "okta_user_session_end"
    tags = ["okta"]


register_event_type(OktaUserSessionEnd)


def post_okta_events(event_hook, data):
    event_observer = EventObserver(**event_hook.observer_dict())
    for event in data["data"]["events"]:
        event_type = event["eventType"]
        if event_type == "user.session.start":
            event_cls = OktaUserSessionStart
        elif event_type == "user.session.end":
            event_cls = OktaUserSessionEnd
        else:
            logger.error("Unknown Okta event type '%s'", event_type)
            continue
        client_d = event.get("client")
        client_ip = client_d.get("ipAddress")
        client_user_agent = client_d.get("userAgent", {}).get("rawUserAgent")
        client_geo = client_d.get("geographicalContext", {})
        if client_geo:
            event_request_geo = EventRequestGeo(country_name=client_geo.get("country"),
                                                city_name=client_geo.get("city"),
                                                region_name=client_geo.get("state"),
                                                location=client_geo.get("geolocation"))
        else:
            event_request_geo = None
        payload = {}
        event_actor = event.get("actor")
        if event_actor:
            payload["actor"] = event_actor
        event_outcome = event.get("outcome")
        if event_outcome:
            payload["outcome"] = event_outcome
        if not payload:
            logger.error("Empty event payload from Okta event")
            continue
        # event
        try:
            created_at = parser.parse(event["published"])
        except (KeyError, TypeError, ValueError):
            logger.error("Could not parse datetime from Okta event")
            created_at = None
        event_metadata = EventMetadata(event_cls.event_type,
                                       request=EventRequest(client_user_agent, client_ip, geo=event_request_geo),
                                       observer=event_observer,
                                       created_at=created_at,
                                       tags=event_cls.tags)
        event = event_cls(event_metadata, payload)
        event.post()
