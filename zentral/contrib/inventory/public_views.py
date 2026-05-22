import logging

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from zentral.utils.http import user_agent_and_ip_address_from_request

from .events import post_enrollment_info_request_event

logger = logging.getLogger("zentral.contrib.inventory.public_views")


class EnrollmentSecretAuthentication(BaseAuthentication):
    """Authenticate via `Authorization: ZtlEnrollmentSecret <secret>` against an Enrollment row.

    Subclasses bind the scheme to a concrete per-module Enrollment model:

        from zentral.contrib.inventory.public_views import EnrollmentSecretAuthentication
        from .models import Enrollment

        class MyEnrollmentSecretAuthentication(EnrollmentSecretAuthentication):
            enrollment_model = Enrollment                                       # the model class

    `enrollment_event_type` is derived from `enrollment_model._meta` to match the EnrollmentSecret
    related_name (`%(app_label)s_%(class)s` on BaseEnrollment.secret).

    Returns (None, enrollment) on success — there's no Django user attached, just the
    Enrollment instance, accessible from the view as request.auth.

    Every denial path posts an enrollment_info_request audit event (with type set to
    `enrollment_event_type`) before raising AuthenticationFailed. authenticate_header is
    intentionally not implemented so DRF returns 403 instead of 401, matching the rest of
    the public API.
    """
    keyword = "ZtlEnrollmentSecret"
    enrollment_model = None
    enrollment_event_type = None

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if cls.enrollment_model is not None:
            meta = cls.enrollment_model._meta
            cls.enrollment_event_type = f"{meta.app_label}_{meta.model_name}"

    def authenticate(self, request):
        if self.enrollment_model is None:
            raise NotImplementedError(
                "EnrollmentSecretAuthentication subclasses must set enrollment_model"
            )
        header = request.META.get("HTTP_AUTHORIZATION") or ""
        prefix = f"{self.keyword} "
        if not header.startswith(prefix):
            self._deny(request, "Missing or invalid Authorization header")
        secret = header[len(prefix):].strip()
        if not secret:
            self._deny(request, "Empty enrollment secret")
        qs = self.enrollment_model.objects
        try:
            enrollment = qs.get(secret__secret=secret)
        except self.enrollment_model.DoesNotExist:
            self._deny(request, "unknown secret")
        is_valid, err_msg = enrollment.secret.is_valid()
        if not is_valid:
            self._deny(request, err_msg, enrollment_pk=enrollment.pk)
        return (None, enrollment)

    def _deny(self, request, reason, enrollment_pk=None):
        logger.warning(
            "Enrollment info request denied (%s): %s",
            self.enrollment_event_type, reason, extra={"request": request},
        )
        user_agent, ip = user_agent_and_ip_address_from_request(request)
        payload = {"status": "denied", "reason": reason}
        if enrollment_pk is not None:
            payload["enrollment"] = {"pk": enrollment_pk}
        post_enrollment_info_request_event(self.enrollment_event_type, user_agent, ip, payload)
        raise AuthenticationFailed(reason)
