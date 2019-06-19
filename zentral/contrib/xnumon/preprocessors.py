import json
import logging
from dateutil import parser
from zentral.contrib.filebeat.utils import (get_serial_number_from_raw_event,
                                            get_user_agent_and_ip_address_from_raw_event)
from .events import (XnumonImageExecEvent, XnumonLaunchdAddEvent, XnumonOpsEvent,
                     XnumonProcessAccessEvent, XnumonStatsEvent)


logger = logging.getLogger("zentral.contrib.xnumon.preprocessors")


class XnumonLogPreprocessor(object):
    routing_key = "xnumon_logs"
    eventcode_mapping = dict((event_class.xnumon_eventcode, event_class)
                             for event_class in (XnumonOpsEvent,
                                                 XnumonStatsEvent,
                                                 XnumonImageExecEvent,
                                                 XnumonProcessAccessEvent,
                                                 XnumonLaunchdAddEvent))

    def process_raw_event(self, raw_event):
        try:
            raw_event_d = json.loads(raw_event)
            serial_number = get_serial_number_from_raw_event(raw_event_d)
            if not serial_number:
                return
            user_agent, ip_address = get_user_agent_and_ip_address_from_raw_event(raw_event_d)
            event_data = raw_event_d["json"]
            event_class = self.eventcode_mapping[int(event_data.pop("eventcode"))]
        except Exception:
            logger.exception("Could not process xnumon_log raw event")
        else:
            if event_class == XnumonImageExecEvent and "image" in event_data:
                # default value for xnumon signature
                # see https://github.com/droe/xnumon/blob/ca644bdc9de04dcb821a4d9012b38f7c7c64a589/codesign.c#L395
                event_data["image"].setdefault("signature", "undefined")
            yield from event_class.build_from_machine_request_payloads(
                serial_number, user_agent, ip_address, [event_data],
                get_created_at=lambda d: parser.parse(d.pop("time"))
            )


def get_preprocessors():
    yield XnumonLogPreprocessor()
