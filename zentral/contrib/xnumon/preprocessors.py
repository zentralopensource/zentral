import json
import logging
from dateutil import parser
from zentral.contrib.filebeat.utils import get_serial_number_from_raw_event
from .events import XnumonImageExecEvent, XnumonLaunchdAddEvent, XnumonOpsEvent, XnumonProcessAccessEvent


logger = logging.getLogger("zentral.contrib.xnumon.preprocessors")


class XnumonLogPreprocessor(object):
    routing_key = "xnumon_logs"
    eventcode_mapping = dict((event_class.xnumon_eventcode, event_class)
                             for event_class in (XnumonOpsEvent,
                                                 XnumonImageExecEvent,
                                                 XnumonProcessAccessEvent,
                                                 XnumonLaunchdAddEvent))

    def process_raw_event(self, raw_event):
        try:
            raw_event_d = json.loads(raw_event)
            serial_number = get_serial_number_from_raw_event(raw_event_d)
            if not serial_number:
                return
            event_data = raw_event_d["json"]
            user_agent = "/".join(raw_event_d.get("agent", {}).get(attr) for attr in ("type", "version"))
            ip_address = raw_event_d.get("filebeat_ip_address")
            event_class = self.eventcode_mapping[int(event_data.pop("eventcode"))]
        except Exception:
            logger.exception("Could not process xnumon_log raw event")
        else:
            yield from event_class.build_from_machine_request_payloads(
                serial_number, user_agent, ip_address, [event_data],
                get_created_at=lambda d: parser.parse(d.pop("time"))
            )


def get_preprocessors():
    yield XnumonLogPreprocessor()
