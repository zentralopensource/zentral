import logging
from zentral.core.events.base import BaseEvent, register_event_type

logger = logging.getLogger('zentral.contrib.osquery.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "osquery"}


class OsqueryEvent(BaseEvent):
    tags = ["osquery"]


class OsqueryEnrollmentEvent(OsqueryEvent):
    event_type = "osquery_enrollment"

register_event_type(OsqueryEnrollmentEvent)


class OsqueryRequestEvent(OsqueryEvent):
    event_type = "osquery_request"

register_event_type(OsqueryRequestEvent)


class OsqueryResultEvent(OsqueryEvent):
    event_type = "osquery_result"

    def get_notification_context(self, probe):
        ctx = super().get_notification_context(probe)
        if 'action' in self.payload:
            ctx['action'] = self.payload['action']
        if 'columns' in self.payload:
            ctx['columns'] = self.payload['columns']
        query_name = self.payload.get("name")
        if query_name:
            try:
                ctx['query'] = probe.scheduled_queries[query_name]
            except AttributeError:
                # not a OsqueryResultProbe
                pass
            except KeyError:
                logger.warning("Unknown query %s", query_name)
                pass
        return ctx

register_event_type(OsqueryResultEvent)


class OsqueryDistributedQueryResultEvent(OsqueryEvent):
    event_type = "osquery_distributed_query_result"

register_event_type(OsqueryDistributedQueryResultEvent)


class OsqueryStatusEvent(OsqueryEvent):
    event_type = "osquery_status"

register_event_type(OsqueryStatusEvent)


# Utility functions used by the osquery enrollment / log API

def post_distributed_query_result(msn, user_agent, ip, payloads):
    OsqueryDistributedQueryResultEvent.post_machine_request_payloads(msn, user_agent, ip, payloads)


def post_events_from_osquery_log(msn, user_agent, ip, data):
    if data["log_type"] == "status":
        event_cls = OsqueryStatusEvent
    elif data["log_type"] == "result":
        event_cls = OsqueryResultEvent
    else:
        raise NotImplementedError("Unknown log type.")
    event_cls.post_machine_request_payloads(msn, user_agent, ip, data['data'])


def post_enrollment_event(msn, user_agent, ip, data):
    OsqueryEnrollmentEvent.post_machine_request_payloads(msn, user_agent, ip, [data])


def post_request_event(msn, user_agent, ip, request_type):
    OsqueryRequestEvent.post_machine_request_payloads(msn, user_agent, ip,
                                                      [{'request_type': request_type}])
