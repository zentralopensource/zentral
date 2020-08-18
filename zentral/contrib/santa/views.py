import json
import logging
from uuid import UUID
import zlib
from django.urls import reverse
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied, SuspiciousOperation
from django.http import Http404, HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.generic import DetailView, ListView, TemplateView, View
from django.views.generic.edit import CreateView, FormView, UpdateView
from zentral.contrib.inventory.conf import macos_version_from_build
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.contrib.inventory.models import Certificate, MachineTag, MetaMachine
from zentral.contrib.inventory.utils import (commit_machine_snapshot_and_trigger_events,
                                             verify_enrollment_secret)
from zentral.core.probes.models import ProbeSource
from zentral.utils.certificates import parse_dn
from zentral.utils.http import user_agent_and_ip_address_from_request
from .conf import build_santa_conf
from .events import post_enrollment_event, post_events, post_preflight_event
from .forms import (CertificateSearchForm, CollectedApplicationSearchForm,
                    ConfigurationForm, CreateProbeForm, EnrollmentForm, RuleForm)
from .models import CollectedApplication, Configuration, EnrolledMachine, Enrollment
from .probes import Rule
from .utils import build_configuration_plist, build_configuration_profile

logger = logging.getLogger('zentral.contrib.santa.views')


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
    template_name = "santa/enrollment_form.html"

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


class EnrollmentConfigurationView(LoginRequiredMixin, View):
    format = None

    def get(self, request, *args, **kwargs):
        enrollment = get_object_or_404(Enrollment, pk=kwargs["pk"], configuration__pk=kwargs["configuration_pk"])
        if self.format == "plist":
            filename, content = build_configuration_plist(enrollment)
            content_type = "application/x-plist"
        elif self.format == "configuration_profile":
            filename, content = build_configuration_profile(enrollment)
            content_type = "application/octet-stream"
        else:
            raise ValueError("Unknown configuration format: {}".format(self.format))
        response = HttpResponse(content, content_type)
        response["Content-Disposition"] = 'attachment; filename="{}"'.format(filename)
        return response


# probes


class CreateProbeView(LoginRequiredMixin, FormView):
    form_class = CreateProbeForm
    template_name = "santa/create_probe.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["probes"] = True
        return ctx

    def form_valid(self, form):
        probe_source = form.save()
        return HttpResponseRedirect(probe_source.get_absolute_url())


class AddProbeRuleView(LoginRequiredMixin, FormView):
    form_class = RuleForm
    template_name = "santa/rule_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        return super().dispatch(request, *args, **kwargs)

    def get_initial(self):
        initial = {}
        self.collected_app = None
        self.certificate = None
        if "app_id" in self.request.GET:
            try:
                self.collected_app = CollectedApplication.objects.get(pk=self.request.GET["app_id"])
            except (KeyError, CollectedApplication.DoesNotExist):
                pass
            else:
                initial["rule_type"] = Rule.BINARY
                initial["sha256"] = self.collected_app.sha_256
        elif "cert_id" in self.request.GET:
            try:
                self.certificate = Certificate.objects.get(pk=self.request.GET["cert_id"])
            except (KeyError, CollectedApplication.DoesNotExist):
                pass
            else:
                initial["rule_type"] = Rule.CERTIFICATE
                initial["sha256"] = self.certificate.sha_256
        return initial

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["collected_app"] = self.collected_app
        kwargs["certificate"] = self.certificate
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['probes'] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['add_rule'] = True
        ctx['cancel_url'] = self.probe_source.get_absolute_url("santa")
        ctx['collected_app'] = self.collected_app
        ctx['certificate'] = self.certificate
        if self.collected_app:
            ctx["title"] = "Add collected application santa rule"
        elif self.certificate:
            ctx["title"] = "Add collected certificate santa rule"
        else:
            ctx["title"] = "Add santa rule"
        return ctx

    def form_valid(self, form):
        rule_d = form.get_rule_d()

        def func(probe_d):
            rules = probe_d.setdefault("rules", [])
            rules.append(rule_d)
        self.probe_source.update_body(func)
        return super().form_valid(form)

    def get_success_url(self):
        return self.probe_source.get_absolute_url("santa")


class UpdateProbeRuleView(LoginRequiredMixin, FormView):
    form_class = RuleForm
    template_name = "santa/rule_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        self.rule_id = int(kwargs["rule_id"])
        try:
            self.rule = self.probe.rules[self.rule_id]
        except IndexError:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_initial(self):
        return self.form_class.get_initial(self.rule)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['probes'] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['add_rule'] = False
        ctx['title'] = "Update santa rule"
        ctx['cancel_url'] = self.probe_source.get_absolute_url("santa")
        return ctx

    def form_valid(self, form):
        rule_d = form.get_rule_d()

        def func(probe_d):
            probe_d["rules"][self.rule_id] = rule_d
        self.probe_source.update_body(func)
        return super().form_valid(form)

    def get_success_url(self):
        return self.probe_source.get_absolute_url("santa")


class DeleteProbeRuleView(LoginRequiredMixin, TemplateView):
    template_name = "santa/delete_rule.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        if not self.probe.can_delete_rules:
            return HttpResponseRedirect(self.probe_source.get_absolute_url("santa"))
        self.rule_id = int(kwargs["rule_id"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['probes'] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['cancel_url'] = self.probe_source.get_absolute_url("santa")
        return ctx

    def post(self, request, *args, **kwargs):
        def func(probe_d):
            probe_d["rules"].pop(self.rule_id)
            if not probe_d["rules"]:
                probe_d.pop("rules")
        self.probe_source.update_body(func)
        return HttpResponseRedirect(self.probe_source.get_absolute_url("santa"))


class PickRuleApplicationView(LoginRequiredMixin, TemplateView):
    template_name = "santa/pick_rule_app.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['probes'] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['cancel_url'] = self.probe_source.get_absolute_url("santa")
        form = CollectedApplicationSearchForm(self.request.GET)
        form.is_valid()
        ctx['apps'] = CollectedApplication.objects.search(**form.cleaned_data)
        ctx['form'] = form
        return ctx


class PickRuleCertificateView(LoginRequiredMixin, TemplateView):
    template_name = "santa/pick_rule_cert.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['probes'] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['cancel_url'] = self.probe_source.get_absolute_url("santa")
        form = CertificateSearchForm(self.request.GET)
        form.is_valid()
        ctx['certs'] = CollectedApplication.objects.search_certificates(**form.cleaned_data)
        ctx['form'] = form
        return ctx


# Sync API


class BaseSyncView(View):
    require_enrolled_machine = True

    def get_client_cert(self):
        dn = self.request.META.get("HTTP_X_SSL_CLIENT_S_DN")
        if dn:
            return parse_dn(dn)
        else:
            return None

    def _get_json_data(self, request):
        payload = request.body
        if not payload:
            return None
        try:
            if request.META.get('HTTP_CONTENT_ENCODING', None) == "zlib":
                payload = zlib.decompress(payload)
            return json.loads(payload)
        except ValueError:
            raise SuspiciousOperation("Could not read JSON data")

    def post(self, request, *args, **kwargs):
        self.enrollment_secret_secret = kwargs["enrollment_secret"]
        try:
            self.hardware_uuid = str(UUID(kwargs["machine_id"]))
        except ValueError:
            raise PermissionDenied("Invalid machine id")
        try:
            self.enrolled_machine = EnrolledMachine.objects.select_related(
                "enrollment__secret",
                "enrollment__configuration"
            ).get(
                enrollment__secret__secret=self.enrollment_secret_secret,
                hardware_uuid=self.hardware_uuid
            )
        except EnrolledMachine.DoesNotExist:
            if self.require_enrolled_machine:
                raise PermissionDenied("Unknown machine")
            self.enrolled_machine = None
        else:
            if self.enrolled_machine.enrollment.configuration.client_certificate_auth and \
               self.get_client_cert() is None:
                raise PermissionDenied("Missing client certificate")
            self.machine_serial_number = self.enrolled_machine.serial_number
            self.business_unit = self.enrolled_machine.enrollment.secret.get_api_enrollment_business_unit()
        data = self._get_json_data(request)
        self.user_agent, self.ip = user_agent_and_ip_address_from_request(request)
        return JsonResponse(self.do_post(data))


class PreflightView(BaseSyncView):
    require_enrolled_machine = False

    def enroll_machine(self, data):
        try:
            enrollment = (Enrollment.objects.select_related("configuration", "secret")
                                    .get(secret__secret=self.enrollment_secret_secret))
        except Enrollment.DoesNotExist:
            raise PermissionDenied("Unknown enrollment secret")
        if enrollment.configuration.client_certificate_auth and self.get_client_cert() is None:
            raise PermissionDenied("Missing client certificate")
        try:
            verify_enrollment_secret(
                "santa_enrollment", self.enrollment_secret_secret,
                self.user_agent, self.ip,
                serial_number=self.machine_serial_number, udid=self.hardware_uuid,
            )
        except EnrollmentSecretVerificationFailed:
            raise PermissionDenied("Wrong enrollment secret")

        # get or create enrolled machine
        self.enrolled_machine, _ = EnrolledMachine.objects.get_or_create(
            enrollment=enrollment,
            hardware_uuid=self.hardware_uuid,
            defaults={"serial_number": self.machine_serial_number}
        )

        # apply enrollment secret tags
        for tag in enrollment.secret.tags.all():
            MachineTag.objects.get_or_create(serial_number=self.machine_serial_number, tag=tag)

        # post event
        post_enrollment_event(self.machine_serial_number, self.user_agent, self.ip, {'action': 'enrollment'})

    def commit_machine_snapshot(self, data):
        # os version
        build = data["os_build"]
        os_version = dict(zip(('major', 'minor', 'patch'),
                              (int(s) for s in data['os_version'].split('.'))))
        os_version.update({'name': 'macOS', 'build': build})
        try:
            os_version.update(macos_version_from_build(build))
        except ValueError:
            pass

        # tree
        tree = {'source': {'module': 'zentral.contrib.santa',
                           'name': 'Santa'},
                'reference': self.hardware_uuid,
                'serial_number': self.machine_serial_number,
                'os_version': os_version,
                'system_info': {'computer_name': data['hostname']},
                'public_ip_address': self.ip,
                }
        if self.business_unit:
            tree['business_unit'] = self.business_unit.serialize()

        commit_machine_snapshot_and_trigger_events(tree)

    def do_post(self, data):
        self.machine_serial_number = data['serial_num']

        if not self.enrolled_machine:
            self.enroll_machine(data)
        self.business_unit = self.enrolled_machine.enrollment.secret.get_api_enrollment_business_unit()

        post_preflight_event(self.enrolled_machine.serial_number,
                             self.user_agent,
                             self.ip,
                             data)

        self.commit_machine_snapshot(data)

        config_dict = {
            'UploadLogsUrl': self.request.build_absolute_uri(reverse('santa:logupload',
                                                                     args=(self.enrollment_secret_secret,
                                                                           self.hardware_uuid,)))
        }
        config_dict.update(
            self.enrolled_machine.enrollment.configuration.get_sync_server_config(data["santa_version"])
        )
        return config_dict


class RuleDownloadView(BaseSyncView):
    def do_post(self, data):
        return build_santa_conf(MetaMachine(self.machine_serial_number))


class EventUploadView(BaseSyncView):
    def do_post(self, data):
        post_events(self.machine_serial_number,
                    self.user_agent,
                    self.ip,
                    data)
        return {}


class LogUploadView(BaseSyncView):
    pass


class PostflightView(BaseSyncView):
    def do_post(self, data):
        return {}
