import json
import logging
from dateutil import parser
from zentral.contrib.filebeat.utils import (get_serial_number_from_raw_event,
                                            get_user_agent_and_ip_address_from_raw_event)
from zentral.contrib.santa.events import SantaLogEvent
from zentral.utils.json import save_dead_letter


logger = logging.getLogger("zentral.contrib.santa.preprocessors.log")


def parse_santa_log_message(message):
    d = {}
    current_attr = ""
    current_val = ""
    state = None
    for c in message:
        if state is None:
            if c == "[":
                current_attr = "timestamp"
                state = "VAL"
            elif c == ":":
                state = "ATTR"
                current_attr = ""
        elif state == "ATTR":
            if c == "=":
                state = "VAL"
            elif current_attr or c != " ":
                current_attr += c
        elif state == "VAL":
            if c == "|" or (current_attr == "timestamp" and c == "]"):
                if c == "|":
                    state = "ATTR"
                elif c == "]":
                    state = None
                if current_attr == "timestamp":
                    current_val = parser.parse(current_val)
                d[current_attr] = current_val
                current_attr = ""
                current_val = ""
            else:
                current_val += c
    if current_attr and current_val:
        d[current_attr] = current_val
    for attr, val in d.items():
        if attr.endswith("id"):
            try:
                d[attr] = int(val)
            except ValueError:
                pass
    args = d.get("args")
    if args:
        d["args"] = args.split()
    return d


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
