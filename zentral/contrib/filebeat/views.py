import json
import logging
from django.core.exceptions import SuspiciousOperation
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.generic import DetailView, ListView, TemplateView, View
from django.views.generic.edit import CreateView, UpdateView
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.contrib.inventory.models import MachineTag
from zentral.contrib.inventory.utils import verify_enrollment_secret
from zentral.utils.http import user_agent_and_ip_address_from_request
from .events import post_enrollment_event
from .forms import ConfigurationForm, EnrollmentForm
from .models import Configuration, EnrolledMachine

logger = logging.getLogger('zentral.contrib.filebeat.views')


# configuration / enrollment


class ConfigurationListView(LoginRequiredMixin, ListView):
    model = Configuration

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["configurations_count"] = ctx["object_list"].count()
        return ctx


class CreateConfigurationView(LoginRequiredMixin, CreateView):
    model = Configuration
    form_class = ConfigurationForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class ConfigurationView(LoginRequiredMixin, DetailView):
    model = Configuration

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        enrollments = list(self.object.enrollment_set.select_related("secret").all().order_by("id"))
        ctx["enrollments"] = enrollments
        ctx["enrollments_count"] = len(enrollments)
        return ctx


class UpdateConfigurationView(LoginRequiredMixin, UpdateView):
    model = Configuration
    form_class = ConfigurationForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class CreateEnrollmentView(LoginRequiredMixin, TemplateView):
    template_name = "filebeat/enrollment_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.configuration = get_object_or_404(Configuration, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_forms(self):
        secret_form_kwargs = {"prefix": "secret"}
        enrollment_form_kwargs = {"configuration": self.configuration,
                                  "initial": {"configuration": self.configuration}}
        if self.request.method == "POST":
            secret_form_kwargs["data"] = self.request.POST
            enrollment_form_kwargs["data"] = self.request.POST
        return (EnrollmentSecretForm(**secret_form_kwargs),
                EnrollmentForm(**enrollment_form_kwargs))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["configuration"] = self.configuration
        if "secret_form" not in kwargs or "enrollment_form" not in kwargs:
            ctx["secret_form"], ctx["enrollment_form"] = self.get_forms()
        return ctx

    def forms_invalid(self, secret_form, enrollment_form):
        return self.render_to_response(self.get_context_data(secret_form=secret_form,
                                                             enrollment_form=enrollment_form))

    def forms_valid(self, secret_form, enrollment_form):
        secret = secret_form.save()
        secret_form.save_m2m()
        enrollment = enrollment_form.save(commit=False)
        enrollment.secret = secret
        if self.configuration:
            enrollment.configuration = self.configuration
        enrollment.save()
        return HttpResponseRedirect(enrollment.get_absolute_url())

    def post(self, request, *args, **kwargs):
        secret_form, enrollment_form = self.get_forms()
        if secret_form.is_valid() and enrollment_form.is_valid():
            return self.forms_valid(secret_form, enrollment_form)
        else:
            return self.forms_invalid(secret_form, enrollment_form)


# enrollment endpoint called by enrollment script


class EnrollView(View):
    def post(self, request, *args, **kwargs):
        self.user_agent, self.ip = user_agent_and_ip_address_from_request(request)
        try:
            request_json = json.loads(request.body.decode("utf-8"))
            secret = request_json["secret"]
            serial_number = request_json["serial_number"]
            uuid = request_json["uuid"]
            es_request = verify_enrollment_secret(
                "filebeat_enrollment", secret,
                self.user_agent, self.ip,
                serial_number, uuid
            )
        except (ValueError, KeyError, EnrollmentSecretVerificationFailed):
            raise SuspiciousOperation
        else:
            # get or create enrolled machine
            enrolled_machine, enrolled_machine_created = EnrolledMachine.objects.get_or_create(
                enrollment=es_request.enrollment_secret.filebeat_enrollment,
                serial_number=serial_number
            )

            # apply enrollment secret tags
            for tag in es_request.enrollment_secret.tags.all():
                MachineTag.objects.get_or_create(serial_number=serial_number, tag=tag)

            # response
            response = {}

            # post event
            post_enrollment_event(serial_number, self.user_agent, self.ip,
                                  {'action': "enrollment" if enrolled_machine_created else "re-enrollment"})
        return JsonResponse(response)
