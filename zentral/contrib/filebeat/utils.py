import json
import logging
from zentral.utils.certificates import parse_dn
from .models import EnrollmentSession


logger = logging.getLogger("zentral.contrib.filebeat.utils")


def get_serial_number_from_enrollment_secret(secret):
    # TODO optimization. Could be cached. With encrypted communications to the cache server (like with the DB) !
    try:
        return (EnrollmentSession.objects.select_related("enrollment_secret")
                                         .get(enrollment_secret__secret=secret)
                                         .enrollment_secret.serial_numbers[0])
    except (EnrollmentSession.DoesNotExist, IndexError):
        pass


def get_serial_number_from_raw_event(raw_event_d):
    try:
        tls_peer = json.loads(raw_event_d.pop("tls_peer"))
        subject = parse_dn(tls_peer["subject"])
        serial_number = subject.get("serialNumber")
        if not serial_number:
            _, secret = subject["CN"].split("$")
            serial_number = get_serial_number_from_enrollment_secret(secret)
        return serial_number
    except Exception:
        logger.exception("Could not extract the S/N from the raw event")


def get_user_agent_and_ip_address_from_raw_event(raw_event_d):
    user_agent = "/".join(raw_event_d.get("agent", {}).get(attr) for attr in ("type", "version"))
    ip_address = raw_event_d.get("filebeat_ip_address")
    return user_agent, ip_address
