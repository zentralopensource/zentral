import logging
import uuid
from dateutil import parser
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest, register_event_type

logger = logging.getLogger('zentral.contrib.munki.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "munki"}


class MunkiEnrollmentEvent(BaseEvent):
    event_type = "munki_enrollment"
    tags = ["munki"]


register_event_type(MunkiEnrollmentEvent)


class MunkiRequestEvent(BaseEvent):
    event_type = "munki_request"
    tags = ["munki", "heartbeat"]
    heartbeat_timeout = 2 * 3600


register_event_type(MunkiRequestEvent)


class BaseMunkiEvent(BaseEvent):
    tags = ["munki"]
    namespace = "munki_event"
    payload_aggregations = [
        ("munki_version", {"type": "terms", "bucket_number": 10, "label": "Munki versions"}),
        ("run_type", {"type": "terms", "bucket_number": 10, "label": "Run types"}),
        ("name", {"type": "table", "bucket_number": 50, "label": "Bundles",
                  "columns": [("name", "Name"),
                              ("version", "Version str.")]}),
    ]

    def get_linked_objects_keys(self):
        keys = {}
        event_type = self.payload.get("type")
        if event_type in ("install", "removal"):
            name = self.payload.get("name")
            if name:
                keys["munki_pkginfo_name"] = [(name,)]
                version = self.payload.get("version")
                if version:
                    keys["munki_pkginfo"] = [(name, version)]
        return keys


class MunkiStartEvent(BaseMunkiEvent):
    event_type = "munki_start"


register_event_type(MunkiStartEvent)


class MunkiWarningEvent(BaseMunkiEvent):
    event_type = "munki_warning"


register_event_type(MunkiWarningEvent)


class MunkiErrorEvent(BaseMunkiEvent):
    event_type = "munki_error"


register_event_type(MunkiErrorEvent)


class MunkiInstallEvent(BaseMunkiEvent):
    event_type = "munki_install"


register_event_type(MunkiInstallEvent)


class MunkiInstallFailedEvent(BaseMunkiEvent):
    event_type = "munki_install_failed"


register_event_type(MunkiInstallFailedEvent)


class MunkiRemovalEvent(BaseMunkiEvent):
    event_type = "munki_removal"


register_event_type(MunkiRemovalEvent)


class MunkiRemovalFailedEvent(BaseMunkiEvent):
    event_type = "munki_removal_failed"


register_event_type(MunkiRemovalFailedEvent)


# utils


def post_munki_request_event(msn, user_agent, ip, **kwargs):
    metadata = EventMetadata(
        machine_serial_number=msn,
        request=EventRequest(user_agent, ip),
        incident_updates=kwargs.pop("incident_updates", [])
    )
    event = MunkiRequestEvent(metadata, kwargs)
    event.post()


def post_munki_events(msn, user_agent, ip, data):
    for report in data:
        events = report.pop('events')
        event_uuid = uuid.uuid4()
        for event_index, (created_at, payload) in enumerate(events):
            # event type
            try:
                failed = int(payload["status"]) != 0
            except (KeyError, ValueError):
                failed = True
            payload_type = payload.get("type")
            if payload_type == "install":
                if failed:
                    event_cls = MunkiInstallFailedEvent
                else:
                    event_cls = MunkiInstallEvent
            elif payload_type == "removal":
                if failed:
                    event_cls = MunkiRemovalFailedEvent
                else:
                    event_cls = MunkiRemovalEvent
            elif payload_type == "warning":
                event_cls = MunkiWarningEvent
            elif payload_type == "error":
                event_cls = MunkiErrorEvent
            elif payload_type == "start":
                event_cls = MunkiStartEvent
            else:
                logger.error("Unknown munki event payload type %s", payload_type)
                continue

            # build event
            metadata = EventMetadata(
                uuid=event_uuid,
                index=event_index,
                machine_serial_number=msn,
                request=EventRequest(user_agent, ip),
                created_at=parser.parse(created_at),
                incident_updates=payload.pop("incident_updates", []),
            )
            payload.update(report)
            event = event_cls(metadata, payload)
            event.post()


def post_munki_enrollment_event(msn, user_agent, ip, data):
    MunkiEnrollmentEvent.post_machine_request_payloads(msn, user_agent, ip, [data])
