import json
import logging
from zentral.core.events.base import EventMetadata
from zentral.core.queues import queues
from .events import AuditEvent
from .record import parse_record


logger = logging.getLogger("zentral.contrib.audit.workers")


class AuditRecordPreprocessor(object):
    name = "audit record preprocessor"
    input_queue_name = "audit_records"

    def build_audit_event(self, raw_event_d):
        try:
            payload = parse_record(raw_event_d["message"])
        except:
            logger.exception("Could not parse audit message")
            return
        else:
            machine_serial_number = raw_event_d["fields"]["machine_serial_number"]
            metadata = EventMetadata(AuditEvent.event_type,
                                     machine_serial_number=machine_serial_number,
                                     created_at=payload.pop("created_at"),
                                     tags=AuditEvent.tags)
            return AuditEvent(metadata, payload)

    def process_raw_event(self, raw_event):
        raw_event_d = json.loads(raw_event)
        event = self.build_audit_event(raw_event_d)
        if event:
            yield event


def get_workers():
    return [queues.get_preprocessor_worker(AuditRecordPreprocessor())]
