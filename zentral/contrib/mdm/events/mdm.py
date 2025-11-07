import logging
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata


logger = logging.getLogger('zentral.contrib.mdm.events.mdm')


class DEPEnrollmentRequestEvent(BaseEvent):
    event_type = "dep_enrollment_request"
    tags = ["mdm", "dep", "heartbeat"]


register_event_type(DEPEnrollmentRequestEvent)


class OTAEnrollmentRequestEvent(BaseEvent):
    event_type = "ota_enrollment_request"
    tags = ["mdm", "ota", "heartbeat"]


register_event_type(OTAEnrollmentRequestEvent)


class UserEnrollmentRequestEvent(BaseEvent):
    event_type = "user_enrollment_request"
    tags = ["mdm"]


register_event_type(UserEnrollmentRequestEvent)


class MDMRequestEvent(BaseEvent):
    event_type = "mdm_request"
    tags = ["mdm", "heartbeat"]


register_event_type(MDMRequestEvent)


class MDMDeviceNotificationEvent(BaseEvent):
    event_type = "mdm_device_notification"
    tags = ["mdm"]


register_event_type(MDMDeviceNotificationEvent)


def build_mdm_device_notification_event(serial_number, udid, priority, expiration_seconds, success, user_id=None):
    event_metadata = EventMetadata(machine_serial_number=serial_number)
    event_payload = {
        "udid": udid,
        "apns_priority": priority,
        "apns_expiration_seconds": expiration_seconds,
        "status": "success" if success else "failure",
    }
    if user_id:
        event_payload["user_id"] = user_id
    return MDMDeviceNotificationEvent(event_metadata, event_payload)


def post_mdm_device_notification_event(serial_number, udid, priority, expiration_seconds, success, user_id=None):
    event = build_mdm_device_notification_event(serial_number, udid, priority, expiration_seconds, success, user_id)
    event.post()
