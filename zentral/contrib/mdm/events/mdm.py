import logging
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest


logger = logging.getLogger('zentral.contrib.mdm.events.mdm')


class EnrollmentRequestEvent(BaseEvent):
    enrollment_payload_key = None

    def get_linked_objects_keys(self):
        enrollment = self.payload.get(self.enrollment_payload_key)
        if not enrollment:
            # the aborted requests do not always have an enrollment session
            return {}
        # same object key as the audit events of the enrollment
        return {f"mdm_{self.enrollment_payload_key}": [(enrollment["pk"],)]}


class DEPEnrollmentRequestEvent(EnrollmentRequestEvent):
    event_type = "dep_enrollment_request"
    enrollment_payload_key = "dep_enrollment"
    tags = ["mdm", "dep", "heartbeat"]


register_event_type(DEPEnrollmentRequestEvent)


class OTAEnrollmentRequestEvent(EnrollmentRequestEvent):
    event_type = "ota_enrollment_request"
    enrollment_payload_key = "ota_enrollment"
    tags = ["mdm", "ota", "heartbeat"]


register_event_type(OTAEnrollmentRequestEvent)


class UserEnrollmentRequestEvent(EnrollmentRequestEvent):
    event_type = "user_enrollment_request"
    enrollment_payload_key = "user_enrollment"
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


def build_mdm_device_notification_event(serial_number, udid, priority, expiration_seconds, success,
                                        user_id=None, request=None):
    # request is only set when an operator asked for the notification, so that poking a device,
    # which changes nothing and therefore has no audit event, is still attributable
    event_metadata = EventMetadata(
        machine_serial_number=serial_number,
        request=EventRequest.build_from_request(request) if request else None,
    )
    event_payload = {
        "udid": udid,
        "apns_priority": priority,
        "apns_expiration_seconds": expiration_seconds,
        "status": "success" if success else "failure",
    }
    if user_id:
        event_payload["user_id"] = user_id
    return MDMDeviceNotificationEvent(event_metadata, event_payload)


def post_mdm_device_notification_event(serial_number, udid, priority, expiration_seconds, success,
                                       user_id=None, request=None):
    event = build_mdm_device_notification_event(
        serial_number, udid, priority, expiration_seconds, success, user_id, request
    )
    event.post()
