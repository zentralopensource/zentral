import logging

from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest, register_event_type
from zentral.utils.http import user_agent_and_ip_address_from_request

logger = logging.getLogger('zentral.contrib.turbo.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "turbo"}


class BaseTurboEvent(BaseEvent):
    tags = ["turbo"]

    def get_linked_objects_keys(self):
        payload = self.payload
        keys = {}
        enrollment = payload.get("enrollment") or {}
        if enrollment.get("pk"):
            keys["turbo_enrollment"] = [(enrollment["pk"],)]
        configuration = payload.get("configuration") or {}
        if configuration.get("pk"):
            keys["turbo_configuration"] = [(configuration["pk"],)]

        def add(key, pk):
            # a job can be scheduled several times in one status report — dedupe
            if pk and (pk,) not in keys.setdefault(key, []):
                keys[key].append((pk,))

        # status entries carry the wire `schedule` {mode, pk}; link the Job and the scheduling row
        for ref in payload.get("jobs", []):
            add("turbo_job", ref.get("pk"))
            schedule = ref.get("schedule") or {}
            if schedule.get("mode") == "recurring":
                add("turbo_recurring_job", schedule.get("pk"))
            elif schedule.get("mode") == "one_time":
                add("turbo_one_time_job", schedule.get("pk"))
        return keys


class TurboRequestEvent(BaseTurboEvent):
    # the agent's periodic check-in — this is the heartbeat
    event_type = "turbo_request"
    tags = ["turbo", "heartbeat"]
    heartbeat_timeout = 2 * 3600


register_event_type(TurboRequestEvent)


class TurboResultEvent(BaseTurboEvent):
    # one per individual job result (the request itself is a TurboRequestEvent); the result entry —
    # kind / pk / run / result — sits at the payload top level, so it links its own Job + scheduling row
    event_type = "turbo_result"

    def get_linked_objects_keys(self):
        keys = super().get_linked_objects_keys()
        if self.payload.get("pk"):
            keys["turbo_job"] = [(self.payload["pk"],)]
        run = self.payload.get("run") or {}
        schedule_pk = run.get("schedule_pk")
        if schedule_pk and run.get("mode") == "recurring":
            keys["turbo_recurring_job"] = [(schedule_pk,)]
        elif schedule_pk and run.get("mode") == "one_time":
            keys["turbo_one_time_job"] = [(schedule_pk,)]
        return keys


register_event_type(TurboResultEvent)


class BaseTurboComplianceCheckStatusUpdated(BaseTurboEvent):
    # one per compliance check whose status changed on a machine (the machine-wide roll-up is a separate
    # MachineComplianceChangeEvent), mirroring osquery / munki so probes can key on a single check flipping.
    # One concrete event per check kind (script / mSCP); both carry the turbo_compliance_check tag so a
    # single query pulls either kind. Abstract: subclasses set event_type and link_key.
    namespace = "compliance_check"
    tags = ["turbo", "compliance_check", "compliance_check_status", "turbo_compliance_check"]
    link_key = None

    @classmethod
    def build(cls, definition, serial_number, status, status_time, previous_status):
        payload = definition.compliance_check.serialize_for_event()
        payload[cls.link_key] = {"pk": str(definition.pk)}
        payload["status"] = status.name
        if previous_status is not None:
            payload["previous_status"] = previous_status.name
        return cls(EventMetadata(machine_serial_number=serial_number, created_at=status_time), payload)

    def get_linked_objects_keys(self):
        keys = {}
        cc_pk = self.payload.get("pk")
        if cc_pk:
            keys["compliance_check"] = [(cc_pk,)]
        ref = self.payload.get(self.link_key) or {}
        if ref.get("pk"):
            keys[self.link_key] = [(ref["pk"],)]
        return keys


class TurboScriptComplianceCheckStatusUpdated(BaseTurboComplianceCheckStatusUpdated):
    event_type = "turbo_script_check_status_updated"
    link_key = "turbo_script"


register_event_type(TurboScriptComplianceCheckStatusUpdated)


class TurboMSCPCheckComplianceCheckStatusUpdated(BaseTurboComplianceCheckStatusUpdated):
    event_type = "turbo_mscp_check_status_updated"
    link_key = "turbo_mscp_check"


register_event_type(TurboMSCPCheckComplianceCheckStatusUpdated)


def _add_enrollment_keys(enrollment, payload):
    # the enrollment + its configuration as top-level keys (kept top-level so linked objects resolve)
    payload["enrollment"] = enrollment.serialize_for_event(keys_only=True)
    payload["configuration"] = enrollment.configuration.serialize_for_event(keys_only=True)
    return payload


def post_turbo_request_event(request, serial_number, enrollment, payload):
    metadata = EventMetadata(
        machine_serial_number=serial_number,
        request=EventRequest.build_from_request(request),
    )
    TurboRequestEvent(metadata, _add_enrollment_keys(enrollment, payload)).post()


def post_turbo_result_events(request, serial_number, enrollment, results):
    # one TurboResultEvent per result, each stamped with that result's run time (created_at), so the
    # event timeline reflects when the job actually ran on the device — not when the server ingested it.
    # The request itself is posted separately by the view as a TurboRequestEvent.
    user_agent, ip = user_agent_and_ip_address_from_request(request)
    payloads = (_add_enrollment_keys(enrollment, result) for result in results)
    TurboResultEvent.post_machine_request_payloads(
        serial_number, user_agent, ip, payloads,
        get_created_at=lambda payload: (payload.get("run") or {}).get("at"))
