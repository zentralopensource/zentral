from datetime import datetime
import logging
from zentral.core.events.base import BaseEvent, register_event_type

logger = logging.getLogger('zentral.contrib.santa.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "santa"}


class SantaPreflightEvent(BaseEvent):
    event_type = "santa_preflight"
    tags = ["santa", "heartbeat"]
    heartbeat_timeout = 2 * 10 * 60


register_event_type(SantaPreflightEvent)


class SantaEventEvent(BaseEvent):
    event_type = "santa_event"
    tags = ["santa"]
    payload_aggregations = [
        ("decision", {"type": "terms", "bucket_number": 10, "label": "Decisions"}),
        ("file_bundle_name", {"type": "terms", "bucket_number": 10, "label": "Bundle names"}),
        ("bundles", {"type": "table", "bucket_number": 100, "label": "Bundles",
                     "columns": [("file_bundle_name", "Name"),
                                 ("file_bundle_id", "ID"),
                                 ("file_bundle_path", "File path"),
                                 ("file_bundle_version_string", "Version str.")]}),
    ]

    def get_notification_context(self, probe):
        ctx = super().get_notification_context(probe)
        if 'decision' in self.payload:
            ctx['decision'] = self.payload['decision']
        if 'file_name' in self.payload:
            ctx['file_name'] = self.payload['file_name']
        if 'file_path' in self.payload:
            ctx['file_path'] = self.payload['file_path']
        return ctx


register_event_type(SantaEventEvent)


def get_created_at(payload):
    return datetime.utcfromtimestamp(payload['execution_time'])


def post_santa_events(msn, user_agent, ip, data):
    SantaEventEvent.post_machine_request_payloads(msn, user_agent, ip,
                                                  data.get('events', []),
                                                  get_created_at)


def post_santa_preflight(msn, user_agent, ip, data):
    SantaPreflightEvent.post_machine_request_payloads(msn, user_agent, ip, [data])
