import logging
from zentral.core.events.base import BaseEvent, EventMetadata, register_event_type


logger = logging.getLogger("zentral.core.compliance_checks.events")


class MachineComplianceChangeEvent(BaseEvent):
    event_type = "machine_compliance_change"
    namespace = "compliance_check"
    tags = ["compliance_check", "compliance_check_status"]

    @classmethod
    def build_from_serial_number_and_statuses(
        cls,
        serial_number,
        status, status_time,
        previous_status
    ):
        payload = {"status": status.name}
        if previous_status is not None:
            payload["previous_status"] = previous_status.name
        return cls(EventMetadata(machine_serial_number=serial_number, created_at=status_time), payload)


register_event_type(MachineComplianceChangeEvent)
