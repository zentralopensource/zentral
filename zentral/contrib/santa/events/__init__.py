import logging
from zentral.core.events.base import BaseEvent, register_event_type

logger = logging.getLogger('zentral.contrib.santa.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "santa"}


class SantaBaseEvent(BaseEvent):
    tags = ["santa"]


class SantaPreflightEvent(SantaBaseEvent):
    event_type = "santa_preflight"

register_event_type(SantaPreflightEvent)


class SantaEventEvent(SantaBaseEvent):
    event_type = "santa_event"

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


def post_santa_events(msn, user_agent, ip, data):
    SantaEventEvent.post_machine_request_payloads(msn, user_agent, ip, data.get('events', []))


def post_santa_preflight(msn, user_agent, ip, data):
    SantaPreflightEvent.post_machine_request_payloads(msn, user_agent, ip, [data])
