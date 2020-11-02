import logging
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest, EventRequestUser, register_event_type
from realms.models import RealmAuthenticationSession


logger = logging.getLogger("server.realms.utils")


ALL_EVENTS_SEARCH_DICT = {"event_type": ["zentral_login", "zentral_logout", "zentral_failed_login"]}

# events


class LoginEvent(BaseEvent):
    event_type = "zentral_login"
    tags = ["zentral"]


register_event_type(LoginEvent)


class LogoutEvent(BaseEvent):
    event_type = "zentral_logout"
    tags = ["zentral"]


register_event_type(LogoutEvent)


class FailedLoginEvent(BaseEvent):
    event_type = "zentral_failed_login"
    tags = ["zentral"]


register_event_type(FailedLoginEvent)


class FailedVerificationEvent(BaseEvent):
    event_type = "zentral_failed_verification"
    tags = ["zentral"]


register_event_type(FailedVerificationEvent)


class VerificationDeviceEvent(BaseEvent):
    event_type = "zentral_verification_device"
    tags = ["zentral"]


register_event_type(VerificationDeviceEvent)


# signals callbacks


def post_event(event_cls, request, user, payload=None):
    if payload is None:
        payload = {}

    # TODO: check if user can be different than request.user
    # remove the following bit if not
    eru = EventRequestUser.build_from_user(user)
    if eru:
        payload["user"] = eru.serialize()
        seabc = request.session.get_expire_at_browser_close()
        payload["session"] = {"expire_at_browser_close": seabc}
        if not seabc:
            payload["session"].update({"expiry_age": request.session.get_expiry_age()})

    # realm user
    payload["realm_session"] = False
    ras_uuid = request.session.get("_realm_authentication_session")
    if ras_uuid:
        try:
            ras = RealmAuthenticationSession.objects.select_related("realm", "user").get(uuid=ras_uuid)
        except RealmAuthenticationSession.DoesNotExist:
            logger.error("Could not find realm authentication session %s", ras_uuid)
        else:
            realm = ras.realm
            payload["realm_session"] = True
            payload["realm_user"] = {"realm": {"uuid": realm.uuid,
                                               "name": str(realm),
                                               "backend": realm.backend},
                                     "session": {"uuid": ras.uuid,
                                                 "created_at": ras.created_at,
                                                 "updated_at": ras.updated_at,
                                                 "expires": ras.expires_at is not None,
                                                 "expires_at": ras.expires_at},
                                     "uuid": ras.user.uuid}

    event_request = EventRequest.build_from_request(request)
    metadata = EventMetadata(event_cls.event_type,
                             request=event_request,
                             tags=event_cls.tags)
    event = event_cls(metadata, payload)
    event.post()


def user_logged_in_callback(sender, request, user, **kwargs):
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
                             request=request,
                             tags=FailedLoginEvent.tags)
    event = FailedLoginEvent(metadata, {k: str(v) for k, v in credentials.items()})
    event.post()


user_login_failed.connect(user_login_failed_callback)


def post_failed_verification_event(request, user):
    post_event(FailedVerificationEvent, request, user)


def post_verification_device_event(request, user, action, verification_device=None):
    if verification_device is None:
        payload = {}
    else:
        payload = {"device": verification_device.serialize_for_event()}
    payload["action"] = action
    post_event(VerificationDeviceEvent, request, user, payload)
