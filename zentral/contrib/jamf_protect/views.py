import json
import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied, SuspiciousOperation
from django.http import HttpResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.views.generic import View, ListView, TemplateView
from zentral.conf import settings
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.contrib.inventory.models import MachineTag
from zentral.contrib.inventory.utils import verify_enrollment_secret
from zentral.utils.http import user_agent_and_ip_address_from_request
from .events import post_enrollment_event, post_event
from .models import EnrolledMachine, Enrollment


logger = logging.getLogger('zentral.contrib.jamf_protect.views')


# setup > Jamf Protect enrollments


class EnrollmentsView(LoginRequiredMixin, ListView):
    model = Enrollment

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["events_url"] = "{}{}".format(settings["api"]["tls_hostname"],
                                          reverse("jamf_protect:events"))
        enrollments_count = len(ctx["object_list"])
        ctx["title"] = "{} Jamf Protect enrollment{}".format(
            enrollments_count,
            "" if enrollments_count == 1 else "s"
        )
        return ctx


class CreateEnrollmentView(LoginRequiredMixin, TemplateView):
    template_name = "jamf_protect/enrollment_form.html"

    def get_form(self):
        secret_form_kwargs = {}
        if self.request.method == "POST":
            secret_form_kwargs["data"] = self.request.POST
        return EnrollmentSecretForm(**secret_form_kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        if "secret_form" not in kwargs:
            ctx["secret_form"] = self.get_form()
        return ctx

    def form_invalid(self, secret_form):
        return self.render_to_response(self.get_context_data(secret_form=secret_form))

    def form_valid(self, secret_form):
        secret = secret_form.save()
        secret_form.save_m2m()
        enrollment = Enrollment.objects.create(secret=secret)
        return redirect(enrollment)

    def post(self, request, *args, **kwargs):
        secret_form = self.get_form()
        if secret_form.is_valid():
            return self.form_valid(secret_form)
        else:
            return self.form_invalid(secret_form)


# Jamf Protect API


class PostEventView(View):
    def get_token(self, request):
        try:
            header = request.META['HTTP_AUTHORIZATION']
        except KeyError:
            raise PermissionDenied("Missing authorization header")
        if not header:
            raise PermissionDenied("Empty authorization header")
        if not header.startswith("Bearer"):
            raise PermissionDenied("Invalid authorization header")
        token = header.replace("Bearer", "").strip()
        if not token:
            raise PermissionDenied("Empty Bearer token")
        return token

    def load_event(self, request):
        try:
            payload = json.loads(request.body)
        except Exception:
            raise SuspiciousOperation("Could not load request body")
        try:
            event = payload["input"]
            serial_number = event["host"]["serial"]
        except KeyError:
            raise SuspiciousOperation("Could not find machine serial number")
        if not serial_number:
            raise SuspiciousOperation("Empty serial number")
        return serial_number, event

    def post(self, request, *args, **kwargs):
        token = self.get_token(request)
        user_agent, ip = user_agent_and_ip_address_from_request(request)
        serial_number, event = self.load_event(request)
        if not EnrolledMachine.objects.filter(enrollment__secret__secret=token,
                                              serial_number=serial_number).count():
            try:
                request = verify_enrollment_secret(
                    "jamf_protect_enrollment", token, user_agent, ip,
                    serial_number=serial_number
                )
            except EnrollmentSecretVerificationFailed:
                raise PermissionDenied("Invalid enrollment secret")
            else:
                # get or create enrolled machine
                enrollment_secret = request.enrollment_secret
                enrolled_machine, _ = EnrolledMachine.objects.get_or_create(
                    enrollment=enrollment_secret.jamf_protect_enrollment,
                    serial_number=serial_number
                )

                # apply enrollment secret tags
                for tag in enrollment_secret.tags.all():
                    MachineTag.objects.get_or_create(serial_number=serial_number, tag=tag)
                post_enrollment_event(serial_number, user_agent, ip, {'action': 'enrollment'})
        post_event(serial_number, user_agent, ip, event)
        return HttpResponse("OK")
