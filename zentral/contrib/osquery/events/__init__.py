import logging
from zentral.conf import probes
from zentral.core.events import BaseEvent, EventMetadata, EventRequest, register_event_type

logger = logging.getLogger('zentral.contrib.osquery.events')

__all__ = ['OsqueryEnrollmentEvent', 'OsqueryResultEvent', 'OsqueryStatusEvent']


class OsqueryEvent(BaseEvent):
    pass


class OsqueryEnrollmentEvent(OsqueryEvent):
    event_type = "osquery_enrollment"


register_event_type(OsqueryEnrollmentEvent)


class OsqueryRequestEvent(OsqueryEvent):
    event_type = "osquery_request"

register_event_type(OsqueryRequestEvent)


def _get_probe_and_query_from_payload(payload):
    """Fetch the corresponding probe and query dict from the config."""
    probe, query = None, None
    try:
        query_name = payload['name']
    except KeyError:
        logger.error("Missing 'name' in event payload")
    else:
        probe_name, probe_query_id = query_name.rsplit('_', 1)
        try:
            probe = probes[probe_name]
        except KeyError:
            logger.error('Unknown probe %s', probe_name)
        else:
            try:
                query = probe['osquery']['schedule'][int(probe_query_id)].copy()
            except KeyError:
                logger.error('Unknown query %s', query_name)
            else:
                query['name'] = query_name
    return probe, query


class OsqueryResultEvent(OsqueryEvent):
    event_type = "osquery_result"

    def __init__(self, *args, **kwargs):
        super(OsqueryResultEvent, self).__init__(*args, **kwargs)
        self.query_probe, self.query = _get_probe_and_query_from_payload(self.payload)

    def _get_extra_context(self):
        ctx = {}
        if self.query_probe:
            ctx['query_probe'] = self.query_probe
        if self.query:
            ctx['query'] = self.query
        if 'action' in self.payload:
            ctx['action'] = self.payload['action']
        if 'columns' in self.payload:
            ctx['columns'] = self.payload['columns']
        return ctx

    def extra_probe_checks(self, probe):
        """Exclude osquery probes if not connected to event."""
        if "osquery" in probe and probe != self.query_probe:
            return False
        else:
            return True

register_event_type(OsqueryResultEvent)


class OsqueryStatusEvent(OsqueryEvent):
    event_type = "osquery_status"


register_event_type(OsqueryStatusEvent)


# Utility functions used by the osquery enrollment / log API


def _payloads_from_osquery_status(data):
    for payload in data['data']:
        yield payload


def _payloads_from_osquery_result(data):
    for osquery_ev in data['data']:
        payload = osquery_ev.copy()
        snapshot = payload.pop('snapshot', None)
        if snapshot:
            # We keep all the tuples together in the same event
            # but we transform the tuple list in a dictionary
            probe, query_conf = _get_probe_and_query_from_payload(payload)
            conf_key = None
            if query_conf:
                conf_key = query_conf.get('key', None)
            snap_d = {}
            for index, columns in enumerate(snapshot):
                if conf_key:
                    key = "|".join([columns[k] for k in conf_key])
                else:
                    key = index
                if key in snap_d:
                    logger.error("Duplicated key %s in query %s", conf_key, query_conf)
                else:
                    snap_d[key] = columns
            payload[payload['name']] = snap_d
            yield payload
        else:
            yield payload


def post_events_from_osquery_log(msn, user_agent, ip, data):
    if data["log_type"] == "status":
        event_cls = OsqueryStatusEvent
        payloads = _payloads_from_osquery_status(data)
    elif data["log_type"] == "result":
        event_cls = OsqueryResultEvent
        payloads = _payloads_from_osquery_result(data)
    else:
        raise NotImplementedError("Unknown log type.")
    metadata = EventMetadata(event_cls.event_type,
                             machine_serial_number=msn,
                             request=EventRequest(user_agent, ip),
                             tags=['osquery'])
    for index, payload in enumerate(payloads):
        metadata.index = index
        event = event_cls(metadata, payload)
        event.post()


def post_enrollment_event(msn, user_agent, ip, data):
    event_cls = OsqueryEnrollmentEvent
    metadata = EventMetadata(event_cls.event_type,
                             machine_serial_number=msn,
                             request=EventRequest(user_agent, ip),
                             tags=['osquery'])
    event = event_cls(metadata, data)
    event.post()


def post_request_event(msn, user_agent, ip, request_type):
    event_cls = OsqueryRequestEvent
    metadata = EventMetadata(event_cls.event_type,
                             machine_serial_number=msn,
                             request=EventRequest(user_agent, ip),
                             tags=['osquery'])
    event = event_cls(metadata, {'request_type': request_type})
    event.post()
