from datetime import timedelta
import logging
from django.utils import timezone
from zentral.contrib.mdm.models import EnrolledDevice
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent
from zentral.core.queues import queues


logger = logging.getLogger('zentral.contrib.mdm.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "mdm"}


class DEPEnrollmentRequestEvent(BaseEvent):
    event_type = "dep_enrollment_request"
    tags = ["mdm", "dep", "heartbeat"]


register_event_type(DEPEnrollmentRequestEvent)


class OTAEnrollmentRequestEvent(BaseEvent):
    event_type = "ota_enrollment_request"
    tags = ["mdm", "ota", "heartbeat"]


register_event_type(OTAEnrollmentRequestEvent)


class MDMSCEPVerificationEvent(BaseEvent):
    event_type = "mdm_scep_verification"
    tags = ["mdm", "heartbeat"]


register_event_type(MDMSCEPVerificationEvent)


class MDMRequestEvent(BaseEvent):
    event_type = "mdm_request"
    tags = ["mdm", "heartbeat"]


register_event_type(MDMRequestEvent)


class MDMDeviceNotificationEvent(BaseEvent):
    event_type = "mdm_device_notification"
    tags = ["mdm"]


register_event_type(MDMDeviceNotificationEvent)


def send_device_notification(enrolled_device, delay=0):
    payload = {"enrolled_device_pk_list": [enrolled_device.pk]}
    if delay:
        not_before = timezone.now() + timedelta(seconds=delay)
        payload["not_before"] = not_before.isoformat()
    queues.post_raw_event("mdm_device_notifications", payload)


def send_mbu_device_notifications(meta_business_unit):
    queues.post_raw_event(
        "mdm_device_notifications",
        {"enrolled_device_pk_list": [d.pk for d in EnrolledDevice.objects.active_in_mbu(meta_business_unit)]}
    )
