import logging
from zentral.contrib.santa import probes_lookup_dict
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
        self.probes = self._get_probes()

    def _get_probes(self):
        # TODO: the whole zentral contrib app works only with sha256

        # We build a list of sha256 that can be use to find the probe.
        sha256_l = []
        file_sha256 = self.payload.get('file_sha256', None)
        if file_sha256:
            sha256_l.append(file_sha256)
        for cert_d in self.payload.get('signing_chain', []):
            cert_sha256 = cert_d.get('sha256', None)
            if cert_sha256:
                sha256_l.append(cert_sha256)

        # We look for the probe.
        found_probes = []
        for sha256 in sha256_l:
            for probe in probes_lookup_dict.get(sha256, []):
                found_probes.append(probe)
        if found_probes:
            found_probes_count = len(found_probes)
            if found_probes_count > 1:
                logger.warning("Found %d matching santa probes for sha256 %s." % (found_probes_count, sha256))
        return found_probes

    def _get_extra_context(self):
        ctx = {}
        if self.probes:
            ctx['probes'] = self.probes
        if 'decision' in self.payload:
            ctx['decision'] = self.payload['decision']
        if 'file_name' in self.payload:
            ctx['file_name'] = self.payload['file_name']
        if 'file_path' in self.payload:
            ctx['file_path'] = self.payload['file_path']
        return ctx

    def extra_probe_checks(self, probe):
        """Exclude santa probes if not connected to event."""
        if "santa" in probe and not probe in self.probes:
            return False
        else:
            return True

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
