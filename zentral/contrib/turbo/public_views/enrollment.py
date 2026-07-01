import hashlib
import json
import logging

from django.core.exceptions import SuspiciousOperation
from django.http import JsonResponse
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.views.generic import View

from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.utils import add_machine_tags, verify_enrollment_secret
from zentral.core.compliance_checks.models import MachineStatus
from zentral.utils.http import user_agent_and_ip_address_from_request
from ..compliance_checks import TurboMSCPCheck, TurboScript
from ..events import post_turbo_request_event
from ..models import EnrolledMachine, MachineJobStatus

logger = logging.getLogger("zentral.contrib.turbo.public_views.enrollment")


class EnrollView(View):
    def post(self, request, *args, **kwargs):
        user_agent, ip = user_agent_and_ip_address_from_request(request)
        try:
            request_json = json.loads(request.body.decode("utf-8"))
            secret = request_json["secret"]
            serial_number = request_json["serial_number"]
            hardware_uuid = request_json["hardware_uuid"]
            es_request = verify_enrollment_secret(
                "turbo_enrollment", secret,
                user_agent, ip,
                serial_number, hardware_uuid,
            )
        except (KeyError, ValueError, EnrollmentSecretVerificationFailed):
            raise SuspiciousOperation
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
        if created and EnrolledMachine.objects.filter(serial_number=serial_number).exclude(
                enrollment__configuration=configuration).exists():
            # the machine re-homed from another configuration — its ledger AND its compliance state
            # belong to the old config, so drop both. Leaving the MachineStatus rows behind would keep
            # the old config's checks contributing to the machine's aggregate compliance forever; they
            # are recomputed from the new config's jobs as results arrive.
            MachineJobStatus.objects.filter(serial_number=serial_number).delete()
            MachineStatus.objects.filter(
                serial_number=serial_number,
                compliance_check__model__in=(TurboScript.get_model(), TurboMSCPCheck.get_model()),
            ).delete()
        add_machine_tags(serial_number, tags, request)
        post_turbo_request_event(
            request, serial_number, enrollment,
            {"request_type": "enrollment",
             "action": "enrollment" if created else "re-enrollment"},
        )
        return JsonResponse({"token": token})
