from dateutil import parser
import json
import logging
from zentral.utils.certificates import parse_dn
from zentral.contrib.filebeat.models import EnrollmentSession
from .events import XnumonLogEvent


logger = logging.getLogger("zentral.contrib.xnumon.preprocessors")


class XnumonLogPreprocessor(object):
    routing_key = "xnumon_logs"

    def process_raw_event(self, raw_event):
        try:
            raw_event_d = json.loads(raw_event)
            tls_peer = json.loads(raw_event_d.pop("tls_peer"))
            subject = parse_dn(tls_peer["subject"])
            subject_prefix, secret = subject["CN"].split("$")
            enrollment_session = (EnrollmentSession.objects.select_related("enrollment_secret")
                                                           .get(enrollment_secret__secret=secret))
            serial_number = enrollment_session.enrollment_secret.serial_numbers[0]
            event_data = raw_event_d["json"]
            user_agent = "/".join(raw_event_d.get("agent", {}).get(attr) for attr in ("type", "version"))
            ip_address = raw_event_d.get("filebeat_ip_address")
        except Exception:
            logger.exception("Could not process xnumon_log raw event")
        else:
            yield from XnumonLogEvent.build_from_machine_request_payloads(
                serial_number, user_agent, ip_address, [event_data],
                get_created_at=lambda d: parser.parse(d.pop("time"))
            )


def get_preprocessors():
    yield XnumonLogPreprocessor()
