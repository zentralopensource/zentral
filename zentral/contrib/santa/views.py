import base64
import json
import logging
from django.core.exceptions import SuspiciousOperation
from django.urls import reverse
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.http import Http404, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils.crypto import get_random_string
from django.views.generic import DetailView, ListView, TemplateView, View
from django.views.generic.edit import CreateView, FormView, UpdateView
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.contrib.inventory.models import Certificate, MachineTag, MetaMachine
from zentral.contrib.inventory.utils import (commit_machine_snapshot_and_trigger_events,
                                             verify_enrollment_secret)
from zentral.core.events.base import post_machine_conflict_event
from zentral.core.probes.models import ProbeSource
from zentral.utils.api_views import APIAuthError, verify_secret, JSONPostAPIView
from zentral.utils.http import user_agent_and_ip_address_from_request
from .conf import build_santa_conf
from .events import post_enrollment_event, post_events, post_preflight_event
from .forms import (CertificateSearchForm, CollectedApplicationSearchForm,
                    ConfigurationForm, CreateProbeForm, EnrollmentForm, RuleForm)
from .models import CollectedApplication, Configuration, EnrolledMachine, Enrollment
from .probes import Rule
from .osx_package.builder import SantaZentralEnrollPkgBuilder
from .utils import build_config_plist, build_configuration_profile

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


class EnrollmentPackageView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        enrollment = get_object_or_404(Enrollment, pk=kwargs["pk"], configuration__pk=kwargs["configuration_pk"])
        builder = SantaZentralEnrollPkgBuilder(enrollment)
        return builder.build_and_make_response()


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
                "santa_enrollment", secret,
                self.user_agent, self.ip,
                serial_number, uuid
            )
        except (ValueError, KeyError, EnrollmentSecretVerificationFailed):
            raise SuspiciousOperation
        else:
            # get or create enrolled machine
            enrolled_machine, enrolled_machine_created = EnrolledMachine.objects.get_or_create(
                enrollment=es_request.enrollment_secret.santa_enrollment,
                serial_number=serial_number,
                defaults={"machine_id": get_random_string(64)}
            )

            # apply enrollment secret tags
            for tag in es_request.enrollment_secret.tags.all():
                MachineTag.objects.get_or_create(serial_number=serial_number, tag=tag)

            # response
            response = {"machine_id": enrolled_machine.machine_id}
            cp_name, cp_content = build_configuration_profile(enrolled_machine)
            cp_content = base64.b64encode(cp_content).decode("utf-8")
            response["configuration_profile"] = {"name": cp_name, "content": cp_content}
            cpl_name, cpl_content = build_config_plist(enrolled_machine)
            response["config_plist"] = {"name": cpl_name, "content": cpl_content}

            # post event
            post_enrollment_event(serial_number, self.user_agent, self.ip,
                                  {'action': "enrollment" if enrolled_machine_created else "re-enrollment"})
        return JsonResponse(response)


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


# API


class BaseView(JSONPostAPIView):
    def verify_enrolled_machine_id(self):
        """Find the corresponding enrolled machine"""
        try:
            self.enrolled_machine = (EnrolledMachine.objects
                                                    .select_related("enrollment__secret__meta_business_unit")
                                                    .get(machine_id=self.machine_id))
        except EnrolledMachine.DoesNotExist:
            raise APIAuthError("Could not authorize the request")
        else:
            self.machine_serial_number = self.enrolled_machine.serial_number
            self.business_unit = self.enrolled_machine.enrollment.secret.get_api_enrollment_business_unit()

    def verify_signed_machine_id(self):
        """Verify the secret signature"""
        # TODO: deprecate and remove
        data = verify_secret(self.machine_id, "zentral.contrib.santa")
        self.machine_serial_number = data.get('machine_serial_number', None)
        self.business_unit = data.get('business_unit', None)

    def check_request_secret(self, request, *args, **kwargs):
        self.enrolled_machine = None
        self.machine_id = kwargs['machine_id']
        if ":" not in self.machine_id:
            # new way, machine_id is an attribute of EnrolledMachine
            self.verify_enrolled_machine_id()
        else:
            # old way
            self.verify_signed_machine_id()


class PreflightView(BaseView):
    def check_data_secret(self, data):
        reported_serial_number = data['serial_num']
        if reported_serial_number != self.machine_serial_number:
            # the SN reported by santa is not the one configured in the enrollment secret
            auth_err = "santa reported SN {} different from enrollment SN {}".format(reported_serial_number,
                                                                                     self.machine_serial_number)
            machine_info = {k: v for k, v in data.items()
                            if k in ("hostname", "os_build", "os_version", "serial_num", "primary_user") and v}
            post_machine_conflict_event(self.request, "zentral.contrib.santa",
                                        reported_serial_number, self.machine_serial_number,
                                        machine_info)
            raise APIAuthError(auth_err)

    @transaction.non_atomic_requests
    def do_post(self, data):
        post_preflight_event(self.machine_serial_number,
                             self.user_agent,
                             self.ip,
                             data)
        os_version = dict(zip(('major', 'minor', 'patch'),
                              (int(s) for s in data['os_version'].split('.'))))
        os_version.update({'name': 'Mac OS X',
                           'build': data['os_build']})
        tree = {'source': {'module': 'zentral.contrib.santa',
                           'name': 'Santa'},
                'serial_number': self.machine_serial_number,
                'os_version': os_version,
                'system_info': {'computer_name': data['hostname']},
                'public_ip_address': self.ip,
                }
        if self.enrolled_machine:
            # new way
            tree["reference"] = self.enrolled_machine.machine_id
        else:
            # old way
            # TODO: remove it
            tree["reference"] = self.machine_serial_number
        if self.business_unit:
            tree['business_unit'] = self.business_unit.serialize()
        commit_machine_snapshot_and_trigger_events(tree)
        config_dict = {'UploadLogsUrl': 'https://{host}{path}'.format(host=self.request.get_host(),
                                                                      path=reverse('santa:logupload',
                                                                                   args=(self.machine_id,)))}
        if self.enrolled_machine:
            config_dict.update(self.enrolled_machine.enrollment.configuration.get_sync_server_config())
        else:
            config_dict['BatchSize'] = Configuration.DEFAULT_BATCH_SIZE
        return config_dict


class RuleDownloadView(BaseView):
    def do_post(self, data):
        return build_santa_conf(MetaMachine(self.machine_serial_number))


class EventUploadView(BaseView):
    def do_post(self, data):
        post_events(self.machine_serial_number,
                    self.user_agent,
                    self.ip,
                    data)
        return {}


class LogUploadView(BaseView):
    pass


class PostflightView(BaseView):
    def do_post(self, data):
        return {}
