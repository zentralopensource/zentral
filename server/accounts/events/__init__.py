from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest, EventRequestUser, register_event_type


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


def post_event(event_cls, request, user):
    request = EventRequest.build_from_request(request)
    payload = {}
    # TODO: check if user can be different than request.user
    # remove the following bit if not
    eru = EventRequestUser.build_from_user(user)
    if eru:
        payload["user"] = eru.serialize()
    metadata = EventMetadata(event_cls.event_type,
                             request=request,
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
    event = FailedLoginEvent(metadata, credentials)
    event.post()


user_login_failed.connect(user_login_failed_callback)
