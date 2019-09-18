import json
import logging
from zentral.utils.certificates import parse_dn
from .models import EnrolledMachine


logger = logging.getLogger("zentral.contrib.filebeat.utils")


def get_tls_peer_identifiers_from_raw_event(raw_event_d):
    serial_number = enrollment_secret_secret = None
    try:
        tls_peer = json.loads(raw_event_d.pop("tls_peer"))
        subject = parse_dn(tls_peer["subject"])
        serial_number = subject.get("serialNumber")
    except Exception:
        logger.exception("Could not extract identifiers from the raw event")
    else:
        try:
            cn_prefix, cn_secret = subject["CN"].split("$")
        except Exception:
            pass
        else:
            if cn_prefix == "FLBT":  # TODO define in one place
                enrollment_secret_secret = cn_secret
    return serial_number, enrollment_secret_secret


def get_serial_number_from_raw_event(raw_event_d):
    serial_number, secret = get_tls_peer_identifiers_from_raw_event(raw_event_d)
    if not serial_number and secret:
        # TODO: optimization: cache
        try:
            serial_number = EnrolledMachine.objects.get(
                enrollment_session__enrollment_secret__secret=secret
            ).serial_number
        except EnrolledMachine.DoesNotExist:
            pass
    return serial_number


def get_user_agent_and_ip_address_from_raw_event(raw_event_d):
    user_agent = "/".join(raw_event_d.get("agent", {}).get(attr) for attr in ("type", "version"))
    ip_address = raw_event_d.get("filebeat_ip_address")
    return user_agent, ip_address
