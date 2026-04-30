import logging

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from zentral.utils.http import user_agent_and_ip_address_from_request

from .events import post_enrollment_info_request_event

logger = logging.getLogger("zentral.contrib.inventory.authentication")


class EnrollmentSecretAuthentication(BaseAuthentication):
    """Authenticate via `Authorization: ZtlEnrollmentSecret <secret>` against an Enrollment row.

    Subclasses bind the scheme to a concrete per-module Enrollment model:

        from zentral.contrib.inventory.authentication import EnrollmentSecretAuthentication
        from .models import Enrollment

        class MyEnrollmentSecretAuthentication(EnrollmentSecretAuthentication):
            enrollment_model = Enrollment                                       # the model class
            enrollment_token = "myapp_enrollment"                               # EnrollmentSecret related_name
            enrollment_select_related = ("secret__meta_business_unit",)        # optional

    Returns (None, enrollment) on success — there's no Django user attached, just the
    Enrollment instance, accessible from the view as request.auth.

    Every denial path posts an enrollment_info_request audit event (with type set to
    `enrollment_token`) before raising AuthenticationFailed. authenticate_header is
    intentionally not implemented so DRF returns 403 instead of 401, matching the rest of
    the public API.
    """
    keyword = "ZtlEnrollmentSecret"
    enrollment_model = None
    enrollment_token = None
    enrollment_select_related = ()

    def authenticate(self, request):
        if self.enrollment_model is None or self.enrollment_token is None:
            raise NotImplementedError(
                "EnrollmentSecretAuthentication subclasses must set enrollment_model and enrollment_token"
            )
        header = request.META.get("HTTP_AUTHORIZATION") or ""
        prefix = f"{self.keyword} "
        if not header.startswith(prefix):
            self._deny(request, "Missing or invalid Authorization header")
        secret = header[len(prefix):].strip()
        if not secret:
            self._deny(request, "Empty enrollment secret")
        qs = self.enrollment_model.objects
        if self.enrollment_select_related:
            qs = qs.select_related(*self.enrollment_select_related)
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
            self.enrollment_token, reason, extra={"request": request},
        )
        user_agent, ip = user_agent_and_ip_address_from_request(request)
        payload = {"status": "denied", "reason": reason}
        if enrollment_pk is not None:
            payload["enrollment"] = {"pk": enrollment_pk}
        post_enrollment_info_request_event(self.enrollment_token, user_agent, ip, payload)
        raise AuthenticationFailed(reason)
