from datetime import datetime
import logging
import uuid
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest, register_event_type
from zentral.contrib.osquery.compliance_checks import ComplianceCheckStatusAggregator
from zentral.contrib.osquery.models import parse_pack_query_configuration_key, EnrolledMachine, Pack, PackQuery

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

    def get_linked_objects_keys(self):
        keys = {}
        enrollment = self.payload.get("enrollment")
        if enrollment:
            enrollment_pk = enrollment.get("pk")
            if enrollment_pk:
                keys["osquery_enrollment"] = [(enrollment_pk,)]
            configuration = enrollment.get("configuration")
            if configuration:
                configuration_pk = configuration.get("pk")
                if configuration_pk:
                    keys["osquery_configuration"] = [(configuration_pk,)]
        return keys

    @classmethod
    def get_machine_heartbeat_timeout(cls, serial_number):
        enrolled_machines = EnrolledMachine.objects.get_for_serial_number(serial_number)
        count = len(enrolled_machines)
        if not count:
            return
        if count > 1:
            logger.warning("Multiple enrolled machines found for %s", serial_number)
        flags = enrolled_machines[0].enrollment.configuration.get_all_flags()
        intervals = []
        for key in ("config_refresh", "distributed_interval"):
            interval = flags.get(key)
            if isinstance(interval, str):
                try:
                    interval = int(interval)
                except ValueError:
                    logger.error("Invalid %s value for enrolled machine %s", key, serial_number)
                    continue
            if interval and isinstance(interval, int) and interval > 0:
                intervals.append(interval)
        if intervals:
            timeout = 2 * max(intervals)
            logger.debug("Osquery request event heartbeat timeout for machine %s: %s", serial_number, timeout)
            return timeout


register_event_type(OsqueryRequestEvent)


class OsqueryResultEvent(OsqueryEvent):
    event_type = "osquery_result"

    def get_notification_context(self, probe):
        ctx = super().get_notification_context(probe)
        if 'action' in self.payload:
            ctx['action'] = self.payload['action']
        if 'columns' in self.payload:
            ctx['columns'] = self.payload['columns']
        return ctx

    def parse_result_name(self):
        name = self.payload.get("name")
        if not name:
            raise ValueError("result query name not found")
        expected_prefix = "pack" + Pack.DELIMITER
        if not name.startswith(expected_prefix):
            raise ValueError("result query name doesn't start with expected prefix")
        configuration_key = name[len(expected_prefix):]
        return parse_pack_query_configuration_key(configuration_key)

    def get_linked_objects_keys(self):
        keys = {}
        try:
            pack_pk, query_pk, _, _ = self.parse_result_name()
        except ValueError as e:
            logger.warning(str(e))
            return keys
        keys["osquery_pack"] = [(pack_pk,)]
        keys["osquery_query"] = [(query_pk,)]
        return keys


register_event_type(OsqueryResultEvent)


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


class OsqueryCheckStatusUpdated(BaseEvent):
    event_type = 'osquery_check_status_updated'
    namespace = 'compliance_check'
    tags = ['compliance_check', 'osquery_check', 'compliance_check_status']

    @classmethod
    def build_from_query_serial_number_and_statuses(
        cls,
        query, distributed_query_pk,
        serial_number,
        status, status_time,
        previous_status
    ):
        payload = query.compliance_check.serialize_for_event()
        payload["osquery_query"] = {"pk": query.pk}
        if distributed_query_pk:
            payload["osquery_run"] = {"pk": distributed_query_pk}
        else:
            try:
                pack = query.packquery.pack
            except PackQuery.DoesNotExist:
                pass
            else:
                payload["osquery_pack"] = {"pk": pack.pk, "name": pack.name}
        payload["status"] = status.name
        if previous_status is not None:
            payload["previous_status"] = previous_status.name
        return cls(EventMetadata(machine_serial_number=serial_number, created_at=status_time), payload)

    def get_linked_objects_keys(self):
        keys = {}
        pk = self.payload.get("pk")
        if pk:
            keys["compliance_check"] = [(pk,)]
        query_pk = self.payload.get("osquery_query", {}).get("pk")
        if query_pk:
            keys["osquery_query"] = [(query_pk,)]
        distributed_query_pk = self.payload.get("osquery_run", {}).get("pk")
        if distributed_query_pk:
            keys["osquery_run"] = [(distributed_query_pk,)]
        pack_pk = self.payload.get("osquery_pack", {}).get("pk")
        if pack_pk:
            keys["osquery_pack"] = [(pack_pk,)]
        return keys


register_event_type(OsqueryCheckStatusUpdated)


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


def post_file_carve_events(msn, user_agent, ip, payloads):
    OsqueryFileCarvingEvent.post_machine_request_payloads(msn, user_agent, ip, payloads)


def _get_record_created_at(payload):
    return datetime.utcfromtimestamp(float(payload.pop('unixTime')))


def _iter_cleaned_up_records(records):
    for record in records:
        for k in ("decorations", "numerics", "calendarTime", "hostIdentifier"):
            if k in record:
                del record[k]
        yield record


def _post_events(msn, user_agent, ip, event_cls, records):
    event_cls.post_machine_request_payloads(
        msn, user_agent, ip,
        _iter_cleaned_up_records(records),
        _get_record_created_at
    )


def post_status_logs(msn, user_agent, ip, logs):
    OsqueryStatusEvent.post_machine_request_payloads(
        msn, user_agent, ip,
        _iter_cleaned_up_records(logs),
        _get_record_created_at
    )


def post_results(msn, user_agent, ip, results):
    event_uuid = uuid.uuid4()
    if user_agent or ip:
        request = EventRequest(user_agent, ip)
    else:
        request = None
    cc_status_agg = ComplianceCheckStatusAggregator(msn)
    for index, result in enumerate(_iter_cleaned_up_records(results)):
        try:
            event_time = _get_record_created_at(result)
        except Exception:
            logger.exception("Could not extract osquery result time")
            event_time = None
        metadata = EventMetadata(uuid=event_uuid, index=index,
                                 machine_serial_number=msn,
                                 request=request,
                                 created_at=event_time)
        event = OsqueryResultEvent(metadata, result)
        try:
            _, query_pk, query_version, event_routing_key = event.parse_result_name()
        except ValueError:
            logger.exception("Could not parse result name")
            query_pk = query_version = event_routing_key = None
        if event_routing_key:
            event.metadata.routing_key = event_routing_key
        event.post()
        snapshot = event.payload.get("snapshot")
        if snapshot is None:
            # no snapshot, cannot be a compliance check
            continue
        if query_pk is not None and query_version is not None:
            cc_status_agg.add_result(query_pk, query_version, event_time, snapshot)
    cc_status_agg.commit_and_post_events()


# Utility function for the audit trail


def post_osquery_pack_update_events(request, pack_data, pack_queries_data):
    event_request = EventRequest.build_from_request(request)
    pack_update_event_metadata = EventMetadata(request=event_request)
    pack_update_event = OsqueryPackUpdateEvent(pack_update_event_metadata, pack_data)
    pack_update_event.post()
    for idx, pack_query_data in enumerate(pack_queries_data):
        pack_query_update_event_metadata = EventMetadata(request=event_request,
                                                         uuid=pack_update_event_metadata.uuid, index=idx + 1)
        pack_query_update_event = OsqueryPackQueryUpdateEvent(pack_query_update_event_metadata, pack_query_data)
        pack_query_update_event.post()
