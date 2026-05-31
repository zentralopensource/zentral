import logging
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest
from zentral.contrib.mdm.declarations.exceptions import (
    TokenDeviceInactiveError,
    TokenSessionNotFoundError,
    TokenSignatureError,
    TokenTargetNotFoundError,
    TokenUserNotFoundError,
)


logger = logging.getLogger("zentral.contrib.mdm.events.downloads")


# Single event class for every download served by the MDM public endpoints
# (mdm_public:acme_credential, scep_credential, profile_download_view,
#  data_asset_download_view, package_manifest, package_file,
#  enterprise_app_download). The outcome field discriminates the cases; the
#  same key carries the same value shape across outcomes (sparser dict — just
#  {"pk": ...} — when a referenced object could not be resolved).


class MDMDownloadEvent(BaseEvent):
    event_type = "mdm_download"
    namespace = "mdm_download"
    tags = ["mdm"]

    def get_linked_objects_keys(self):
        keys = {}
        dev = self.payload.get("enrolled_device")
        if dev and "pk" in dev:
            keys["mdm_enrolleddevice"] = [(dev["pk"],)]
        usr = self.payload.get("enrolled_user")
        if usr and "pk" in usr:
            keys["mdm_enrolleduser"] = [(usr["pk"],)]
        for target_key in ("cert_asset", "data_asset", "profile", "enterprise_app"):
            target = self.payload.get(target_key)
            if not target:
                continue
            if "pk" in target:
                keys["mdm_artifactversion"] = [(target["pk"],)]
            artifact = target.get("artifact") or {}
            if "pk" in artifact:
                keys["mdm_artifact"] = [(artifact["pk"],)]
        pkg = self.payload.get("package")
        if pkg and "pk" in pkg:
            keys["mdm_package"] = [(pkg["pk"],)]
        session = self.payload.get("enrollment_session")
        if session and "pk" in session and "model" in session:
            keys[f"mdm_{session['model']}"] = [(session["pk"],)]
        return keys


register_event_type(MDMDownloadEvent)


def post_mdm_download_event(
    request,
    *,
    outcome,
    target_type=None,
    target_key=None,
    target_payload=None,
    enrolled_device=None,
    enrolled_user=None,
    response_kind=None,
):
    payload = {"outcome": outcome}
    if target_type:
        payload["target_type"] = target_type
    if target_key and target_payload is not None:
        payload[target_key] = target_payload
    if response_kind:
        payload["response_kind"] = response_kind
    if enrolled_device is not None:
        payload["enrolled_device"] = enrolled_device.serialize_for_event()
    if enrolled_user is not None:
        payload["enrolled_user"] = enrolled_user.serialize_for_event()
    metadata = EventMetadata(
        machine_serial_number=enrolled_device.serial_number if enrolled_device is not None else None,
        request=EventRequest.build_from_request(request),
    )
    MDMDownloadEvent(metadata, payload).post()


def post_mdm_download_error_event(request, view, exception):
    """Post an MDMDownloadEvent for a failed token resolution.

    The exception type drives the outcome and which payload keys are
    populated. Same-named keys keep the same shape across outcomes: a dict
    with at least "pk" — sparser when the referenced object did not resolve.
    """
    payload = {}
    enrolled_device = None
    if isinstance(exception, TokenSignatureError):
        payload["outcome"] = "bad_token"
    elif isinstance(exception, TokenTargetNotFoundError):
        payload["outcome"] = "target_not_found"
        payload["target_type"] = view.target_type
        payload[view.target_key] = {"pk": str(exception.target_pk)}
    elif isinstance(exception, TokenSessionNotFoundError):
        payload["outcome"] = "session_not_found"
        payload["target_type"] = view.target_type
        payload[view.target_key] = exception.target.serialize_for_event()
        payload["enrollment_session"] = {
            "model": exception.session_model,
            "pk": str(exception.session_pk),
        }
    elif isinstance(exception, TokenUserNotFoundError):
        enrolled_device = exception.enrollment_session.enrolled_device
        payload["outcome"] = "user_not_found"
        payload["target_type"] = view.target_type
        payload[view.target_key] = exception.target.serialize_for_event()
        if enrolled_device is not None:
            payload["enrolled_device"] = enrolled_device.serialize_for_event()
        payload["enrolled_user"] = {"pk": str(exception.user_pk)}
    elif isinstance(exception, TokenDeviceInactiveError):
        enrolled_device = exception.enrollment_session.enrolled_device
        payload["outcome"] = "device_inactive"
        payload["target_type"] = view.target_type
        payload[view.target_key] = exception.target.serialize_for_event()
        if enrolled_device is not None:
            payload["enrolled_device"] = enrolled_device.serialize_for_event()
        payload["reason"] = exception.reason
    else:
        raise ValueError(f"Unexpected exception: {type(exception).__name__}")
    metadata = EventMetadata(
        machine_serial_number=enrolled_device.serial_number if enrolled_device is not None else None,
        request=EventRequest.build_from_request(request),
    )
    MDMDownloadEvent(metadata, payload).post()
