from dateutil import parser
import json
import logging
from zentral.utils.certificates import parse_dn
from zentral.contrib.filebeat.models import EnrollmentSession
from .events import SantaLogEvent


logger = logging.getLogger("zentral.contrib.santa.preprocessors")


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
            if c == "|" or c == "]":
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
        try:
            raw_event_d = json.loads(raw_event)
            tls_peer = json.loads(raw_event_d.pop("tls_peer"))
            subject = parse_dn(tls_peer["subject"])
            subject_prefix, secret = subject["CN"].split("$")
            enrollment_session = (EnrollmentSession.objects.select_related("enrollment_secret")
                                                           .get(enrollment_secret__secret=secret))
            serial_number = enrollment_session.enrollment_secret.serial_numbers[0]
            event_data = parse_santa_log_message(raw_event_d["message"])
            user_agent = "/".join(raw_event_d.get("agent", {}).get(attr) for attr in ("type", "version"))
            ip_address = raw_event_d.get("filebeat_ip_address")
        except Exception:
            logger.exception("Could not process santa_log raw event")
        else:
            yield from SantaLogEvent.build_from_machine_request_payloads(
                serial_number, user_agent, ip_address, [event_data],
                get_created_at=lambda d: d.pop("timestamp", None)
            )


def get_preprocessors():
    yield SantaLogPreprocessor()
