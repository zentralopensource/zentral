import hashlib
import json
import logging

from django.core.exceptions import RequestDataTooBig
from django.http import JsonResponse
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.views.generic import View

from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.public_views import BaseEnrollmentInfoView, EnrollmentSecretAuthentication
from zentral.contrib.inventory.utils import add_machine_tags, verify_enrollment_secret
from zentral.core.compliance_checks.models import MachineStatus
from zentral.utils.http import user_agent_and_ip_address_from_request
from ..compliance_checks import TurboMSCPCheck, TurboScript
from ..events import post_turbo_enrollment_event
from ..models import EnrolledMachine, Enrollment, OneTimeJobMachine, RecurringJobMachine
from ..serializers import EnrollmentInfoSerializer
from ..wire import WireEnrollSerializer
from .base import WireError, WireErrorMixin

logger = logging.getLogger("zentral.contrib.turbo.public_views.enrollment")


class TurboEnrollmentSecretAuthentication(EnrollmentSecretAuthentication):
    enrollment_model = Enrollment


class EnrollmentInfoView(BaseEnrollmentInfoView):
    """Return the enrollment's info (its current version) — the agent polls it to notice a bump."""
    authentication_classes = [TurboEnrollmentSecretAuthentication]
    serializer_class = EnrollmentInfoSerializer
    queryset = Enrollment.objects.all()  # hint for drf-spectacular; runtime uses get_object()


class EnrollView(WireErrorMixin, View):
    def post(self, request, *args, **kwargs):
        user_agent, ip = user_agent_and_ip_address_from_request(request)
        try:
            request_json = json.loads(request.body.decode("utf-8"))
        except RequestDataTooBig:
            raise WireError("payload_too_large")
        except (UnicodeDecodeError, ValueError):
            raise WireError("invalid_json")
        if not isinstance(request_json, dict):
            raise WireError("invalid_json")
        serializer = WireEnrollSerializer(data=request_json)
        # one opaque code for both a bad body and a failed secret check: an unauthenticated caller
        # must not learn which (or why the secret was refused — quota, constraints, revocation, …)
        if not serializer.is_valid():
            raise WireError("invalid_enrollment")
        serial_number = serializer.validated_data["serial_number"]
        try:
            es_request = verify_enrollment_secret(
                "turbo_enrollment", serializer.validated_data["secret"],
                user_agent, ip,
                serial_number, serializer.validated_data["hardware_uuid"],
            )
        except EnrollmentSecretVerificationFailed:
            raise WireError("invalid_enrollment")
        enrollment = es_request.enrollment_secret.turbo_enrollment
        tags = list(es_request.enrollment_secret.tags.all())
        # the server stores only sha256(token); the plaintext is returned once and re-enroll rotates it
        token = get_random_string(64)
        enrolled_machine, created = EnrolledMachine.objects.update_or_create(
            enrollment=enrollment,
            serial_number=serial_number,
            defaults={"token_hash": hashlib.sha256(token.encode("utf-8")).hexdigest(),
                      "last_seen_at": timezone.now()},
        )
        configuration = enrollment.configuration
        # delete the superseded enrolled machines (like santa/osquery): the machine holds a single
        # token, so any other row is dead weight whose token must stop working immediately
        other_enrolled_machines = EnrolledMachine.objects.filter(
            serial_number=serial_number).exclude(pk=enrolled_machine.pk)
        other_configuration_ids = set(
            other_enrolled_machines.values_list("enrollment__configuration_id", flat=True))
        other_enrolled_machines.delete()
        if other_configuration_ids - {configuration.pk}:
            # the machine re-homed from another configuration — its per-machine trackers AND its
            # compliance state belong to the old config, so drop both. Leaving the MachineStatus rows
            # behind would keep the old config's checks contributing to the machine's aggregate
            # compliance forever; they are recomputed from the new config's jobs as results arrive.
            OneTimeJobMachine.objects.filter(serial_number=serial_number).delete()
            RecurringJobMachine.objects.filter(serial_number=serial_number).delete()
            MachineStatus.objects.filter(
                serial_number=serial_number,
                compliance_check__model__in=(TurboScript.get_model(), TurboMSCPCheck.get_model()),
            ).delete()
        add_machine_tags(serial_number, tags, request)
        action = "enrollment" if created and not other_configuration_ids else "re-enrollment"
        post_turbo_enrollment_event(request, serial_number, enrollment, action)
        return JsonResponse({"token": token})
