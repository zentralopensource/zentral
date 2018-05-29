from datetime import datetime
import logging
from zentral.core.events.base import BaseEvent, register_event_type
from zentral.core.queues import queues

logger = logging.getLogger('zentral.contrib.osquery.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "osquery"}


class OsqueryEvent(BaseEvent):
    tags = ["osquery"]


class OsqueryEnrollmentEvent(OsqueryEvent):
    event_type = "osquery_enrollment"


register_event_type(OsqueryEnrollmentEvent)


class OsqueryRequestEvent(OsqueryEvent):
    event_type = "osquery_request"
    tags = ['osquery', 'heartbeat']
    heartbeat_timeout = 2 * 60


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
    payload_aggregations = [
        ("empty", {"type": "terms", "bucket_number": 2, "label": "Empty?"}),
        ("error", {"type": "terms", "bucket_number": 2, "label": "Error?"}),
    ]


register_event_type(OsqueryDistributedQueryResultEvent)


class OsqueryFileCarveEvent(OsqueryEvent):
    event_type = "osquery_file_carve"


register_event_type(OsqueryFileCarveEvent)


class OsqueryStatusEvent(OsqueryEvent):
    event_type = "osquery_status"


register_event_type(OsqueryStatusEvent)


# Utility functions used by the osquery enrollment / log API

def post_distributed_query_result(msn, user_agent, ip, payloads):
    OsqueryDistributedQueryResultEvent.post_machine_request_payloads(msn, user_agent, ip, payloads)


def post_file_carve_events(msn, user_agent, ip, payloads):
    OsqueryFileCarveEvent.post_machine_request_payloads(msn, user_agent, ip, payloads)


def post_finished_file_carve_session(session_id):
    queues.post_raw_event("osquery_finished_file_carve_session",
                          {"session_id": session_id})


def get_osquery_result_created_at(payload):
    return datetime.utcfromtimestamp(float(payload['unixTime']))


def post_events_from_osquery_log(msn, user_agent, ip, data):
    if data["log_type"] == "status":
        event_cls = OsqueryStatusEvent
        get_created_at = None
    elif data["log_type"] == "result":
        event_cls = OsqueryResultEvent
        get_created_at = get_osquery_result_created_at
    else:
        raise NotImplementedError("Unknown log type.")
    event_cls.post_machine_request_payloads(msn, user_agent, ip, data['data'], get_created_at)


def post_enrollment_event(msn, user_agent, ip, data):
    OsqueryEnrollmentEvent.post_machine_request_payloads(msn, user_agent, ip, [data])


def post_request_event(msn, user_agent, ip, request_type, enrollment):
    data = {"request_type": request_type}
    if enrollment:
        configuration = enrollment.configuration
        data["enrollment"] = {"pk": enrollment.pk,
                              "configuration": {"pk": configuration.pk,
                                                "name": configuration.name}}
    OsqueryRequestEvent.post_machine_request_payloads(msn, user_agent, ip, [data])
