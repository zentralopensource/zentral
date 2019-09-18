import json
import logging
from zentral.contrib.filebeat.utils import (get_serial_number_from_raw_event,
                                            get_user_agent_and_ip_address_from_raw_event)
from zentral.contrib.santa.events import SantaLogEvent
from zentral.contrib.santa.utils import parse_santa_log_message
from zentral.utils.json import save_dead_letter


logger = logging.getLogger("zentral.contrib.santa.preprocessors.log")


class SantaLogPreprocessor(object):
    routing_key = "santa_logs"

    def process_raw_event(self, raw_event):
        raw_event_d = None
        try:
            raw_event_d = json.loads(raw_event)
            serial_number = get_serial_number_from_raw_event(raw_event_d)
            if not serial_number:
                return
            user_agent, ip_address = get_user_agent_and_ip_address_from_raw_event(raw_event_d)
            event_data = parse_santa_log_message(raw_event_d["message"])
        except Exception:
            logger.exception("Could not process santa_log raw event")
            if raw_event_d:
                save_dead_letter(raw_event_d, "santa log preprocessing error")
        else:
            if event_data:
                yield from SantaLogEvent.build_from_machine_request_payloads(
                    serial_number, user_agent, ip_address, [event_data],
                    get_created_at=lambda d: d.pop("timestamp", None)
                )
            else:
                # probably a log rotation line
                logger.info("Empty santa log event data.")
