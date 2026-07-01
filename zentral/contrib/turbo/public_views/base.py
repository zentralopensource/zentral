import gzip
import hashlib
import json
import logging

from django.core.exceptions import SuspiciousOperation
from django.http import JsonResponse
from django.utils import timezone
from django.views.generic import View

from zentral.utils.http import user_agent_and_ip_address_from_request
from ..events import post_turbo_request_event
from ..models import EnrolledMachine

logger = logging.getLogger("zentral.contrib.turbo.public_views.base")


class BaseEnrolledMachineView(View):
    """Authenticate the agent by the `Authorization: TurboEnrolledMachine <token>` header (matched on sha256)."""

    # at most one EnrolledMachine.last_seen_at write per machine per this many seconds (admin heartbeat)
    last_seen_update_interval = 60

    # every (authenticated, successful) request emits one TurboRequestEvent; subclasses set the request
    # type and may set self.request_event_payload to a summary of what was posted (never the content)
    request_type = None
    request_event_payload = None

    def authenticate(self, request):
        authorization = request.META.get("HTTP_AUTHORIZATION", "")
        if not authorization.startswith("TurboEnrolledMachine "):
            return None
        token = authorization[len("TurboEnrolledMachine "):].strip()
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        # token_hash is unique/indexed, so this is a single keyed lookup — no need to cache it
        try:
            enrolled_machine = (
                EnrolledMachine.objects
                .select_related("enrollment__configuration", "enrollment__secret__meta_business_unit")
                .get(token_hash=token_hash)
            )
        except EnrolledMachine.DoesNotExist:
            return None
        return enrolled_machine

    def dispatch(self, request, *args, **kwargs):
        enrolled_machine = self.authenticate(request)
        if enrolled_machine is None:
            return JsonResponse({"error": "unauthenticated"}, status=401)
        self.enrolled_machine = enrolled_machine
        self.enrollment = enrolled_machine.enrollment
        self.serial_number = enrolled_machine.serial_number
        self.configuration = self.enrollment.configuration
        self.business_unit = self.enrollment.secret.get_api_enrollment_business_unit()
        self.user_agent, self.ip = user_agent_and_ip_address_from_request(request)
        self._stamp_last_seen()
        response = super().dispatch(request, *args, **kwargs)
        if self.request_type and response.status_code == 200:
            post_turbo_request_event(request, self.serial_number, self.enrollment,
                                     {"request_type": self.request_type, **(self.request_event_payload or {})})
        return response

    def _stamp_last_seen(self):
        # cheap admin "last seen" heartbeat: at most one UPDATE per machine per
        # LAST_SEEN_UPDATE_INTERVAL, reusing the row authenticate() already loaded (no extra read)
        now = timezone.now()
        last_seen = self.enrolled_machine.last_seen_at
        if last_seen is None or (now - last_seen).total_seconds() >= self.last_seen_update_interval:
            EnrolledMachine.objects.filter(pk=self.enrolled_machine.pk).update(last_seen_at=now)
            self.enrolled_machine.last_seen_at = now


class BaseEnrolledMachinePostView(BaseEnrolledMachineView):
    """Base for the agent's JSON POST endpoints: read (and optionally gunzip) the body, hand the
    decoded payload to do_post(), and wrap its dict in a JsonResponse."""

    def get_json_data(self, request):
        # gzip is the one Content-Encoding the agent uses: standard, and available out of the box on
        # both ends (Python's gzip, the agent's libz). We control both sides, so there is nothing else
        # to accept — any other body is read as is.
        payload = request.body
        if request.META.get("HTTP_CONTENT_ENCODING") == "gzip":
            try:
                payload = gzip.decompress(payload)
            except (OSError, EOFError):
                raise SuspiciousOperation("Could not decompress request body")
        try:
            return json.loads(payload)
        except ValueError:
            raise SuspiciousOperation("Invalid JSON payload")

    def post(self, request, *args, **kwargs):
        return JsonResponse(self.do_post(self.get_json_data(request)))
