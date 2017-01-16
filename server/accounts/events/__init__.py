from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest, register_event_type


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


# signals callbacks


def make_event_metadata_request(request):
    user_agent = request.META.get("HTTP_USER_AGENT")
    ip = request.META.get("HTTP_X_REAL_IP")
    if user_agent or ip:
        return EventRequest(user_agent, ip)


def make_event_payload(user):
    if not user or not user.is_authenticated:
        return None
    return {"user": {"id": user.pk,
                     "username": user.username,
                     "email": user.email,
                     "is_remote": user.is_remote,
                     "is_superuser": user.is_superuser}}


def post_event(event_cls, request, user):
    payload = make_event_payload(user)
    if not payload:
        return
    metadata = EventMetadata(event_cls.event_type,
                             request=make_event_metadata_request(request),
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
        request = make_event_metadata_request(request)
    metadata = EventMetadata(FailedLoginEvent.event_type,
                             request=request,
                             tags=FailedLoginEvent.tags)
    event = FailedLoginEvent(metadata, credentials)
    event.post()


user_login_failed.connect(user_login_failed_callback)
