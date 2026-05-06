from django.core.cache import cache
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from zentral.contrib.inventory.authentication import EnrollmentSecretAuthentication

from .models import EnrolledMachine, Enrollment


class MunkiEnrollmentSecretAuthentication(EnrollmentSecretAuthentication):
    name = "ztlMunkiEnrollmentSecret"
    enrollment_model = Enrollment


class MunkiEnrolledMachineAuthentication(BaseAuthentication):
    """Authenticate the agent via `Authorization: MunkiEnrolledMachine <token>`.

    Returns (None, enrolled_machine) on success — `request.auth` is the EnrolledMachine
    row, with the enrollment / configuration / secret / mbu prefetched and cached for 10
    minutes by token.

    authenticate_header is intentionally not implemented so DRF returns 403 (not 401),
    matching the behavior of the (now-replaced) BaseView.
    """
    keyword = "MunkiEnrolledMachine"
    cache_timeout = 600

    def authenticate(self, request):
        header = request.META.get("HTTP_AUTHORIZATION") or ""
        prefix = f"{self.keyword} "
        if not header.startswith(prefix):
            raise AuthenticationFailed("Missing or invalid Authorization header")
        token = header[len(prefix):].strip()
        if not token:
            raise AuthenticationFailed("Empty enrolled-machine token")
        enrolled_machine = self._get_enrolled_machine(token)
        if enrolled_machine is None:
            raise AuthenticationFailed("Enrolled machine does not exist")
        return (None, enrolled_machine)

    def _get_enrolled_machine(self, token):
        cache_key = f"munki.{token}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
        try:
            enrolled_machine = (
                EnrolledMachine.objects
                .select_related(
                    "enrollment__configuration",
                    "enrollment__secret__meta_business_unit",
                )
                .get(token=token)
            )
        except EnrolledMachine.DoesNotExist:
            return None
        cache.set(cache_key, enrolled_machine, timeout=self.cache_timeout)
        return enrolled_machine