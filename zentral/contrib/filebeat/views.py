import json
import logging
from django.core.exceptions import SuspiciousOperation
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.generic import DetailView, ListView, TemplateView, View
from django.views.generic.edit import CreateView, UpdateView
from pygments import lexers, highlight
from pygments.formatters import HtmlFormatter
from zentral.conf import settings
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.contrib.inventory.models import MachineTag
from zentral.contrib.inventory.utils import verify_enrollment_secret
from zentral.utils.api_views import BaseVerifySCEPCSRView
from zentral.utils.certificates import parse_dn
from zentral.utils.http import user_agent_and_ip_address_from_request
from .conf import available_inputs, build_filebeat_yml
from .events import FilebeatEnrollmentEvent, post_enrollment_event
from .forms import ConfigurationForm, EnrollmentForm
from .linux_script.builder import ZentralFilebeatEnrollmentScriptBuilder
from .models import Configuration, EnrolledMachine, Enrollment, EnrollmentSession
from .osx_package.builder import ZentralFilebeatPkgBuilder

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
        ctx["input_forms"] = available_inputs.forms_for_context()
        return ctx

    def form_valid(self, form):
        configuration = form.save(commit=False)
        _, serialized_inputs = available_inputs.serialized_inputs(self.request.POST)
        configuration.inputs = serialized_inputs
        configuration.save()
        return redirect(configuration)


class ConfigurationView(LoginRequiredMixin, DetailView):
    model = Configuration

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        lexer = lexers.get_lexer_by_name("yaml")
        formatter = HtmlFormatter()
        ctx["filebeat_yml"] = highlight(build_filebeat_yml(self.object), lexer, formatter)
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
        ctx["input_forms"] = available_inputs.forms_for_context(self.object.inputs)
        return ctx

    def form_valid(self, form):
        configuration = form.save(commit=False)
        _, serialized_inputs = available_inputs.serialized_inputs(self.request.POST)
        configuration.inputs = serialized_inputs
        configuration.save()
        return redirect(configuration)


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


class EnrollmentPackageView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        enrollment = get_object_or_404(Enrollment, pk=kwargs["pk"], configuration__pk=kwargs["configuration_pk"])
        builder = ZentralFilebeatPkgBuilder(enrollment)
        return builder.build_and_make_response()


class EnrollmentScriptView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        enrollment = get_object_or_404(Enrollment, pk=kwargs["pk"], configuration__pk=kwargs["configuration_pk"])
        builder = ZentralFilebeatEnrollmentScriptBuilder(enrollment)
        return builder.build_and_make_response()


# enrollment endpoints called by enrollment script


class StartEnrollmentView(View):
    def post(self, request, *args, **kwargs):
        self.user_agent, self.ip = user_agent_and_ip_address_from_request(request)
        try:
            request_json = json.loads(request.body.decode("utf-8"))
            secret = request_json["secret"]
            serial_number = request_json["serial_number"]
            es_request = verify_enrollment_secret(
                "filebeat_enrollment", secret,
                self.user_agent, self.ip,
                serial_number
            )
        except (ValueError, KeyError, EnrollmentSecretVerificationFailed):
            raise SuspiciousOperation
        else:
            enrollment_session = EnrollmentSession.objects.create_from_enrollment(
                enrollment=es_request.enrollment_secret.filebeat_enrollment,
                serial_number=serial_number
            )
            # response
            response = {
                "scep": {
                    "cn": enrollment_session.get_common_name(),
                    "org": enrollment_session.get_organization(),
                    "challenge": enrollment_session.get_challenge(),
                    "url": "{}/scep".format(settings["api"]["tls_hostname"]),  # TODO: hardcoded scep url
                },
                "secret": enrollment_session.enrollment_secret.secret,
            }

            # post event
            post_enrollment_event(serial_number, self.user_agent, self.ip, enrollment_session.serialize_for_event())
        return JsonResponse(response)


class CompleteEnrollmentView(View):
    def post(self, request, *args, **kwargs):
        # DN => serial_number + meta_business_unit
        dn = request.META.get("HTTP_X_SSL_CLIENT_S_DN")
        if not dn:
            raise SuspiciousOperation("missing DN in request headers")

        dn_d = parse_dn(dn)

        cn = dn_d.get("CN")
        try:
            cn_prefix, enrollment_secret_secret = cn.split("$")
        except (AttributeError, ValueError):
            raise SuspiciousOperation("missing or bad CN in client certificate DN")

        # verify prefix
        if cn_prefix != "FLBT":
            raise SuspiciousOperation("bad CN prefix in client certificate")

        self.user_agent, self.ip = user_agent_and_ip_address_from_request(request)
        try:
            request_json = json.loads(request.body.decode("utf-8"))
            secret = request_json["secret"]
            serial_number = request_json["serial_number"]
            es_request = verify_enrollment_secret(
                "filebeat_enrollment_session", secret,
                self.user_agent, self.ip,
                serial_number,
                filebeat_enrollment_session__status__in=(EnrollmentSession.STARTED, EnrollmentSession.SCEP_VERIFIED)
            )
            certificate = request_json["certificate"]
            key = request_json["key"]
            certificate_authority = request_json["certificate_authority"]
        except (ValueError, KeyError, EnrollmentSecretVerificationFailed):
            raise SuspiciousOperation("Could not verify enrollment session secret")
        else:
            # update enrollment session
            enrollment_session = es_request.enrollment_secret.filebeat_enrollment_session
            enrolled_machine, _ = EnrolledMachine.objects.get_or_create(serial_number=serial_number)
            enrollment_session.set_completed(enrolled_machine)
            # apply enrollment secret tags
            for tag in es_request.enrollment_secret.tags.all():
                MachineTag.objects.get_or_create(serial_number=serial_number, tag=tag)
            # post event
            post_enrollment_event(serial_number, self.user_agent, self.ip, enrollment_session.serialize_for_event())
            # response
            response = {
                "filebeat.yml": build_filebeat_yml(enrollment_session.enrollment.configuration,
                                                   certificate=certificate, key=key,
                                                   certificate_authority=certificate_authority)
            }
            return JsonResponse(response)


# SCEP verification


class VerifySCEPCSRView(BaseVerifySCEPCSRView):
    event_class = FilebeatEnrollmentEvent

    def get_enrollment_session_info(self, cn_prefix):
        if cn_prefix == "FLBT":
            return "filebeat_enrollment_session", EnrollmentSession.STARTED, "set_scep_verified_status"
        else:
            self.abort("Unknown CN prefix {}".format(cn_prefix))
