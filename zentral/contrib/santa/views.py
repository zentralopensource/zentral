import logging
from django.core.urlresolvers import reverse
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.views.generic import TemplateView, View
from django.views.generic.edit import FormView
from zentral.conf import settings
from zentral.contrib.inventory.models import Certificate, MachineSnapshot, MetaBusinessUnit, MetaMachine
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events
from zentral.core.events.base import post_machine_conflict_event
from zentral.core.probes.models import ProbeSource
from zentral.utils.api_views import (make_secret, APIAuthError,
                                     SignedRequestJSONPostAPIView, BaseEnrollmentView, BaseInstallerPackageView)
from .conf import build_santa_conf
from .events import post_santa_events, post_santa_preflight
from .forms import CertificateSearchForm, CollectedApplicationSearchForm, CreateProbeForm, RuleForm
from .models import CollectedApplication
from .probes import Rule
from .osx_package.builder import SantaZentralEnrollPkgBuilder

logger = logging.getLogger('zentral.contrib.santa.views')


class EnrollmentView(LoginRequiredMixin, BaseEnrollmentView):
    builder = SantaZentralEnrollPkgBuilder
    template_name = "santa/enrollment.html"


class EnrollmentDebuggingView(LoginRequiredMixin, View):
    debugging_template = """machine_serial_number="0123456789"
machine_id="%(secret)s\$SERIAL\$$machine_serial_number"
# rule download
curl -XPOST -k %(tls_hostname)s/santa/ruledownload/$machine_id | jq ."""

    def get(self, request, *args, **kwargs):
        try:
            mbu = MetaBusinessUnit.objects.get(pk=int(request.GET['mbu_id']))
            # -> BaseInstallerPackageView
            # TODO Race. The meta_business_unit could maybe be without any api BU.
            # TODO. Better selection if multiple BU ?
            bu = mbu.api_enrollment_business_units()[0]
        except (KeyError, ValueError):
            bu = None
        secret = make_secret("zentral.contrib.santa", bu)
        debugging_tools = self.debugging_template % {'secret': secret,
                                                     'tls_hostname': settings['api']['tls_hostname']}
        return HttpResponse(debugging_tools)


class InstallerPackageView(LoginRequiredMixin, BaseInstallerPackageView):
    module = "zentral.contrib.santa"
    builder = SantaZentralEnrollPkgBuilder
    template_name = "santa/enrollment.html"


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
        ctx['certs'] = Certificate.objects.search(**form.cleaned_data)
        ctx['form'] = form
        return ctx


# API


class BaseView(SignedRequestJSONPostAPIView):
    verify_module = "zentral.contrib.santa"

    def get_request_secret(self, request, *args, **kwargs):
        self.machine_id = kwargs['machine_id']
        return self.machine_id


class PreflightView(BaseView):
    def check_data_secret(self, data):
        reported_serial_number = data['serial_num']
        if reported_serial_number != self.machine_serial_number:
            # the SN reported by osquery is not the one configured in the enrollment secret
            auth_err = "osquery reported SN {} different from enrollment SN {}".format(reported_serial_number,
                                                                                       self.machine_serial_number)
            machine_info = {k: v for k, v in data.items()
                            if k in ("hostname", "os_build", "os_version", "serial_num", "primary_user") and v}
            post_machine_conflict_event(self.request, "zentral.contrib.santa",
                                        reported_serial_number, self.machine_serial_number,
                                        machine_info)
            raise APIAuthError(auth_err)

    @transaction.non_atomic_requests
    def do_post(self, data):
        post_santa_preflight(self.machine_serial_number,
                             self.user_agent,
                             self.ip,
                             data)
        os_version = dict(zip(('major', 'minor', 'patch'),
                              (int(s) for s in data['os_version'].split('.'))))
        os_version.update({'name': 'Mac OS X',
                           'build': data['os_build']})
        tree = {'source': {'module': 'zentral.contrib.santa',
                           'name': 'Santa'},
                'reference': self.machine_serial_number,
                'serial_number': self.machine_serial_number,
                'os_version': os_version,
                'system_info': {'computer_name': data['hostname']},
                'public_ip_address': self.ip,
                }
        if self.business_unit:
            tree['business_unit'] = self.business_unit.serialize()
        commit_machine_snapshot_and_trigger_events(tree)
        return {'BatchSize': 20,  # TODO: ???
                'UploadLogsUrl': 'https://{host}{path}'.format(host=self.request.get_host(),
                                                               path=reverse('santa:logupload',
                                                                            args=(self.machine_id,)))}


class RuleDownloadView(BaseView):
    def do_post(self, data):
        return build_santa_conf(MetaMachine(self.machine_serial_number))


class EventUploadView(BaseView):
    def do_post(self, data):
        try:
            ms = MachineSnapshot.objects.current().get(source__module='zentral.contrib.santa',
                                                       reference=self.machine_serial_number)
        except MachineSnapshot.DoesNotExist:
            machine_serial_number = "UNKNOWN"
            logger.error("Machine ID not found", extra={'request': self.request})
        else:
            machine_serial_number = ms.serial_number
        post_santa_events(machine_serial_number,
                          self.user_agent,
                          self.ip,
                          data)
        return {}


class LogUploadView(BaseView):
    pass


class PostflightView(BaseView):
    def do_post(self, data):
        return {}
