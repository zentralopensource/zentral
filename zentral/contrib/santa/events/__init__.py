import logging
from zentral.conf import probes
from zentral.core.events import BaseEvent, EventMetadata, EventRequest, register_event_type

logger = logging.getLogger('zentral.contrib.santa.events')

__all__ = ['post_santa_events', 'post_santa_preflight', 'SantaEventEvent', 'SantaPreflightEvent']


class SantaBaseEvent(BaseEvent):
    pass


class SantaPreflightEvent(SantaBaseEvent):
    event_type = "santa_preflight"

register_event_type(SantaPreflightEvent)


class SantaEventEvent(SantaBaseEvent):
    event_type = "santa_event"

    def __init__(self, *args, **kwargs):
        super(SantaEventEvent, self).__init__(*args, **kwargs)
        self.probe = self._get_probe()

    def _get_probe(self):
        # TODO: unique sha in whole config ? FASTER ???!!! CERTIFICATE ?
        sha256 = self.payload.get('file_sha256', None)
        if sha256:
            for probe_name, probe_d in probes.items():
                for santa_rule_d in  probe_d.get('santa', []):
                    if santa_rule_d.get('sha256', None) == sha256:
                        return probe_d

    def _get_extra_context(self):
        ctx = {}
        if self.machine:
            ctx['machine'] = self.machine
        if self.probe:
            ctx['probe'] = self.probe
        if 'decision' in self.payload:
            ctx['decision'] = self.payload['decision']
        if 'file_name' in self.payload:
            ctx['file_name'] = self.payload['file_name']
        if 'file_path' in self.payload:
            ctx['file_path'] = self.payload['file_path']
        return ctx

register_event_type(SantaEventEvent)


def _post_santa_events(event_cls, msn, user_agent, ip, payloads):
    metadata = EventMetadata(event_cls.event_type,
                             machine_serial_number=msn,
                             request=EventRequest(user_agent, ip))
    for index, payload in enumerate(payloads):
        metadata.index = index
        event = event_cls(metadata, payload)
        event.post()


def post_santa_events(msn, user_agent, ip, data):
    payloads = data.get('events', [])
    _post_santa_events(SantaEventEvent, msn, user_agent, ip, payloads)


def post_santa_preflight(msn, user_agent, ip, data):
    payloads = [data]
    _post_santa_events(SantaPreflightEvent, msn, user_agent, ip, payloads)
