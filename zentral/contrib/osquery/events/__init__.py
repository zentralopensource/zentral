import logging
from zentral.contrib.osquery.conf import queries_lookup_dict
from zentral.contrib.osquery.probes import OSQueryProbe
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


class OsqueryResultEvent(OsqueryEvent):
    event_type = "osquery_result"

    def __init__(self, *args, **kwargs):
        super(OsqueryResultEvent, self).__init__(*args, **kwargs)
        self._set_probe_and_query_from_payload()

    def _set_probe_and_query_from_payload(self):
        """Fetch the corresponding probe and query dict from the config."""
        self.query_probe, self.query = None, None
        if not self.payload:
            logger.error("Missing payload")
        else:
            try:
                query_name = self.payload['name']
            except KeyError:
                logger.error("Missing 'name' in event payload")
            else:
                try:
                    self.query_probe, self.query = queries_lookup_dict[query_name]
                except KeyError:
                    logger.error('Unknown query %s', query_name)

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
        return not isinstance(probe, OSQueryProbe) or probe == self.query_probe

register_event_type(OsqueryResultEvent)


class OsqueryStatusEvent(OsqueryEvent):
    event_type = "osquery_status"


register_event_type(OsqueryStatusEvent)


# Utility functions used by the osquery enrollment / log API

def post_events_from_osquery_log(msn, user_agent, ip, data):
    if data["log_type"] == "status":
        event_cls = OsqueryStatusEvent
    elif data["log_type"] == "result":
        event_cls = OsqueryResultEvent
    else:
        raise NotImplementedError("Unknown log type.")
    metadata = EventMetadata(event_cls.event_type,
                             machine_serial_number=msn,
                             request=EventRequest(user_agent, ip),
                             tags=['osquery'])
    for index, payload in enumerate(data['data']):
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
