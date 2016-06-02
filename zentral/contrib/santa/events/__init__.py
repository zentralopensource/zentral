import logging
from zentral.contrib.santa.conf import probes_lookup_dict
from zentral.contrib.santa.probes import SantaProbe
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
        super(SantaBaseEvent, self).__init__(*args, **kwargs)
        self._set_rule_probes()

    def _set_rule_probes(self):
        """Find the probes that could have triggered the event."""
        # TODO: the whole zentral contrib app works only with sha256
        # TODO: we could do a better job and try to match the policy
        #       with the santa event "decision" attr and remove some extra matching probes

        # We build a list of sha256 that can be use to find the probes.
        sha256_l = []
        file_sha256 = self.payload.get('file_sha256', None)
        if file_sha256:
            sha256_l.append(file_sha256)
        for cert_d in self.payload.get('signing_chain', []):
            cert_sha256 = cert_d.get('sha256', None)
            if cert_sha256:
                sha256_l.append(cert_sha256)

        # We look for the probes.
        self.rule_probes = []
        for sha256 in sha256_l:
            self.rule_probes.extend(probes_lookup_dict.get(sha256, []))

    def _get_extra_context(self):
        ctx = {}
        if self.rule_probes:
            ctx['rule_probes'] = self.rule_probes
        if 'decision' in self.payload:
            ctx['decision'] = self.payload['decision']
        if 'file_name' in self.payload:
            ctx['file_name'] = self.payload['file_name']
        if 'file_path' in self.payload:
            ctx['file_path'] = self.payload['file_path']
        return ctx

    def extra_probe_checks(self, probe):
        """Exclude santa probes if not connected to event."""
        return not isinstance(probe, SantaProbe) or probe in self.rule_probes

register_event_type(SantaEventEvent)


def _post_santa_events(event_cls, msn, user_agent, ip, payloads):
    metadata = EventMetadata(event_cls.event_type,
                             machine_serial_number=msn,
                             request=EventRequest(user_agent, ip),
                             tags=['santa'])
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
