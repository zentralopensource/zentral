from datetime import datetime
import logging
import uuid
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest, register_event_type


logger = logging.getLogger("server.realms.utils")


ALL_EVENTS_SEARCH_DICT = {"event_type": ["zentral_login", "zentral_logout", "zentral_failed_login"]}

# events


class BaseZentralEvent(BaseEvent):
    namespace = "zentral"
    tags = ["zentral"]


class LoginEvent(BaseZentralEvent):
    event_type = "zentral_login"


register_event_type(LoginEvent)


class LogoutEvent(BaseZentralEvent):
    event_type = "zentral_logout"


register_event_type(LogoutEvent)


class FailedLoginEvent(BaseZentralEvent):
    event_type = "zentral_failed_login"


register_event_type(FailedLoginEvent)


class FailedVerificationEvent(BaseZentralEvent):
    event_type = "zentral_failed_verification"


register_event_type(FailedVerificationEvent)


class CreateVerificationDeviceEvent(BaseZentralEvent):
    event_type = "zentral_create_verification_device"


register_event_type(CreateVerificationDeviceEvent)


class DeleteVerificationDeviceEvent(BaseZentralEvent):
    event_type = "zentral_delete_verification_device"


register_event_type(DeleteVerificationDeviceEvent)


class AddUserToGroupEvent(BaseZentralEvent):
    event_type = "zentral_add_user_to_group"


register_event_type(AddUserToGroupEvent)


class RemoveUserFromGroupEvent(BaseZentralEvent):
    event_type = "zentral_remove_user_from_group"


register_event_type(RemoveUserFromGroupEvent)


# signals callbacks


def post_event(event_cls, request, user, payload=None):
    if payload is None:
        payload = {}
    event_request = EventRequest.build_from_request(request)
    metadata = EventMetadata(event_cls.event_type,
                             namespace=event_cls.namespace,
                             request=event_request,
                             tags=event_cls.tags)
    if user and user != request.user:
        payload["user"] = {"pk": user.pk, "username": user.username}
    event = event_cls(metadata, payload)
    event.post()


def user_logged_in_callback(sender, request, user, **kwargs):
    # login from the force_login test client method is not going through the middlewares
    if hasattr(request, "user"):
        post_event(LoginEvent, request, user)


user_logged_in.connect(user_logged_in_callback)


def user_logged_out_callback(sender, request, user, **kwargs):
    post_event(LogoutEvent, request, user)


user_logged_out.connect(user_logged_out_callback)


def user_login_failed_callback(sender, credentials, **kwargs):
    request = kwargs.get("request")  # introduced in django 1.11
    if request:
        request = EventRequest.build_from_request(request)
    metadata = EventMetadata(FailedLoginEvent.event_type,
                             namespace=FailedLoginEvent.namespace,
                             request=request,
                             tags=FailedLoginEvent.tags)
    event = FailedLoginEvent(metadata, {"user": {k: str(v) for k, v in credentials.items() if k in ("username",)}})
    event.post()


user_login_failed.connect(user_login_failed_callback)


def post_failed_verification_event(request, form):
    post_event(FailedVerificationEvent, request, form.user, {"verification_device": {"type": form.device_type}})


def post_verification_device_event(request, user, action, verification_device=None):
    if action == "create":
        event_class = CreateVerificationDeviceEvent
    elif action == "delete":
        event_class = DeleteVerificationDeviceEvent
    else:
        raise ValueError("Unknown verification device action: {action}")
    if verification_device is None:
        payload = {}
    else:
        payload = {"verification_device": verification_device.serialize_for_event()}
    post_event(event_class, request, user, payload)


def post_group_membership_updates(request, added_groups, removed_groups, user=None):
    event_request = EventRequest.build_from_request(request)
    created_at = datetime.utcnow()
    event_uuid = uuid.uuid4()
    event_index = 0
    base_payload = {}
    if user:
        base_payload["user"] = {
            "pk": user.pk, "username": user.username,
            "is_service_account": user.is_service_account
        }
    if added_groups:
        event_metadata = EventMetadata(AddUserToGroupEvent.event_type,
                                       namespace=AddUserToGroupEvent.namespace,
                                       request=event_request,
                                       tags=AddUserToGroupEvent.tags,
                                       uuid=event_uuid,
                                       created_at=created_at)
        for added_group in added_groups:
            event_metadata.index = event_index
            payload = base_payload.copy()
            payload["group"] = {"pk": added_group.pk, "name": added_group.name}
            event = AddUserToGroupEvent(event_metadata, payload)
            event.post()
            event_index += 1
    if removed_groups:
        event_metadata = EventMetadata(RemoveUserFromGroupEvent.event_type,
                                       namespace=RemoveUserFromGroupEvent.namespace,
                                       request=event_request,
                                       tags=RemoveUserFromGroupEvent.tags,
                                       uuid=event_uuid,
                                       created_at=created_at)
        for removed_group in removed_groups:
            event_metadata.index = event_index
            payload = base_payload.copy()
            payload["group"] = {"pk": removed_group.pk, "name": removed_group.name}
            event = RemoveUserFromGroupEvent(event_metadata, payload)
            event.post()
            event_index += 1
