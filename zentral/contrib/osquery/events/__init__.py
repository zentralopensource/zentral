from datetime import datetime
import logging
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest, register_event_type
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


class OsqueryFileCarvingEvent(OsqueryEvent):
    event_type = "osquery_file_carving"


register_event_type(OsqueryFileCarvingEvent)


class OsqueryStatusEvent(OsqueryEvent):
    event_type = "osquery_status"


register_event_type(OsqueryStatusEvent)


# Audit trail events


class OsqueryPackUpdateEvent(OsqueryEvent):
    event_type = "osquery_pack_update"


register_event_type(OsqueryPackUpdateEvent)


class OsqueryPackQueryUpdateEvent(OsqueryEvent):
    event_type = "osquery_pack_query_update"


register_event_type(OsqueryPackQueryUpdateEvent)


# Utility functions used by the osquery API views


def post_enrollment_event(msn, user_agent, ip, data):
    OsqueryEnrollmentEvent.post_machine_request_payloads(msn, user_agent, ip, [data])


def post_request_event(msn, user_agent, ip, request_type, enrollment):
    configuration = enrollment.configuration
    data = {"request_type": request_type,
            "enrollment": {"pk": enrollment.pk,
                           "configuration": {"pk": configuration.pk,
                                             "name": configuration.name}}}
    OsqueryRequestEvent.post_machine_request_payloads(msn, user_agent, ip, [data])


def post_distributed_query_result(msn, user_agent, ip, payloads):
    OsqueryDistributedQueryResultEvent.post_machine_request_payloads(msn, user_agent, ip, payloads)


def post_file_carve_events(msn, user_agent, ip, payloads):
    OsqueryFileCarvingEvent.post_machine_request_payloads(msn, user_agent, ip, payloads)


def post_finished_file_carve_session(session_id):
    queues.post_raw_event("osquery_finished_file_carve_session",
                          {"session_id": session_id})


def _get_osquery_log_record_created_at(payload):
    return datetime.utcfromtimestamp(float(payload.pop('unixTime')))


def _post_events_from_osquery_log(msn, user_agent, ip, event_cls, records):
    for record in records:
        for k in ("decorations", "numerics", "calendarTime", "hostIdentifier"):
            if k in record:
                del record[k]
    event_cls.post_machine_request_payloads(msn, user_agent, ip, records, _get_osquery_log_record_created_at)


def post_results(msn, user_agent, ip, results):
    _post_events_from_osquery_log(msn, user_agent, ip, OsqueryResultEvent, results)


def post_status_logs(msn, user_agent, ip, logs):
    _post_events_from_osquery_log(msn, user_agent, ip, OsqueryStatusEvent, logs)


# Utility function for the audit trail


def post_osquery_pack_update_events(request, pack_data, pack_queries_data):
    event_request = EventRequest.build_from_request(request)
    pack_update_event_metadata = EventMetadata(OsqueryPackUpdateEvent.event_type, request=event_request)
    pack_update_event = OsqueryPackUpdateEvent(pack_update_event_metadata, pack_data)
    pack_update_event.post()
    for idx, pack_query_data in enumerate(pack_queries_data):
        pack_query_update_event_metadata = EventMetadata(OsqueryPackQueryUpdateEvent.event_type, request=event_request,
                                                         uuid=pack_update_event_metadata.uuid, index=idx + 1)
        pack_query_update_event = OsqueryPackQueryUpdateEvent(pack_query_update_event_metadata, pack_query_data)
        pack_query_update_event.post()
