import json
import logging
from uuid import UUID
import zlib
from django.urls import reverse
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.cache import cache
from django.core.exceptions import PermissionDenied, SuspiciousOperation
from django.db.models import F
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.generic import DetailView, ListView, TemplateView, View
from django.views.generic.edit import CreateView, DeleteView, FormView, UpdateView
from zentral.contrib.inventory.conf import macos_version_from_build
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.contrib.inventory.models import Certificate, File, MachineTag, MetaMachine, PrincipalUserSource
from zentral.contrib.inventory.utils import (commit_machine_snapshot_and_trigger_events,
                                             verify_enrollment_secret)
from zentral.utils.certificates import parse_dn
from zentral.utils.http import user_agent_and_ip_address_from_request
from .events import post_enrollment_event, process_events, post_preflight_event
from .forms import (BinarySearchForm, BundleSearchForm, CertificateSearchForm,
                    ConfigurationForm, EnrollmentForm, RuleForm, RuleSearchForm, UpdateRuleForm)
from .models import Bundle, Configuration, EnrolledMachine, Enrollment, MachineRule, Rule, Target
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
        ctx["rules_count"] = self.object.rule_set.count()
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
    response_type = None

    def get(self, request, *args, **kwargs):
        enrollment = get_object_or_404(Enrollment, pk=kwargs["pk"], configuration__pk=kwargs["configuration_pk"])
        if self.response_type == "plist":
            filename, content = build_configuration_plist(enrollment)
            content_type = "application/x-plist"
        elif self.response_type == "configuration_profile":
            filename, content = build_configuration_profile(enrollment)
            content_type = "application/octet-stream"
        else:
            raise ValueError("Unknown enrollment configuration response type: {}".format(self.response_type))
        response = HttpResponse(content, content_type)
        response["Content-Disposition"] = 'attachment; filename="{}"'.format(filename)
        return response


# rules


class ConfigurationRulesView(LoginRequiredMixin, ListView):
    paginate_by = 10
    template_name = "santa/configuration_rules.html"

    def dispatch(self, request, *args, **kwargs):
        self.configuration = get_object_or_404(Configuration, pk=kwargs["configuration_pk"])
        self.form = RuleSearchForm(self.request.GET, configuration=self.configuration)
        self.form.is_valid()
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        return self.form.get_queryset()

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.configuration
        ctx["form"] = self.form
        page = ctx["page_obj"]
        if page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = page.next_page_number()
            ctx['next_url'] = "?{}".format(qd.urlencode())
        if page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = page.previous_page_number()
            ctx['previous_url'] = "?{}".format(qd.urlencode())
        if page.number > 1:
            qd = self.request.GET.copy()
            qd.pop('page', None)
            ctx['reset_link'] = "?{}".format(qd.urlencode())
        return ctx


class CreateConfigurationRuleView(LoginRequiredMixin, FormView):
    form_class = RuleForm
    template_name = "santa/rule_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.configuration = get_object_or_404(Configuration, pk=kwargs["configuration_pk"])
        self.binary = self.bundle = self.certificate = None
        try:
            self.binary = File.objects.get(pk=self.request.GET["bin"])
        except (KeyError, File.DoesNotExist):
            pass
        try:
            self.bundle = Bundle.objects.select_related("target").get(pk=self.request.GET["bun"])
        except (KeyError, Bundle.DoesNotExist):
            pass
        try:
            self.certificate = Certificate.objects.get(pk=self.request.GET["cert"])
        except (KeyError, Certificate.DoesNotExist):
            pass
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["configuration"] = self.configuration
        kwargs["binary"] = self.binary
        kwargs["bundle"] = self.bundle
        kwargs["certificate"] = self.certificate
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['setup'] = True
        ctx['configuration'] = self.configuration
        if self.binary:
            ctx['files'] = [self.binary]
            ctx['target_type_display'] = "Binary"
            ctx['target_sha256'] = self.binary.sha_256
        else:
            ctx["files"] = []
        if self.bundle:
            ctx['bundle'] = self.bundle
            ctx['target_type_display'] = "Bundle"
            ctx['target_sha256'] = self.bundle.target.sha256
        if self.certificate:
            ctx['certificates'] = [self.certificate]
            ctx['target_type_display'] = "Certificate"
            ctx['target_sha256'] = self.certificate.sha_256
        else:
            ctx["certificates"] = []
        if self.binary:
            ctx["title"] = "Add Santa binary rule"
        elif self.bundle:
            ctx["title"] = "Add Santa bundle rule"
        elif self.certificate:
            ctx["title"] = "Add Santa certificate rule"
        else:
            ctx["title"] = "Add Santa rule"
        return ctx

    def form_valid(self, form):
        rule = form.save()
        return redirect(rule)


class UpdateConfigurationRuleView(LoginRequiredMixin, UpdateView):
    form_class = UpdateRuleForm

    def get_object(self):
        rule = get_object_or_404(
            Rule.objects.select_related("configuration", "target"),
            pk=self.kwargs["pk"],
            configuration__pk=self.kwargs["configuration_pk"],
            ruleset__isnull=True
        )
        self.old_custom_msg = rule.custom_msg
        return rule

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['setup'] = True
        ctx["configuration"] = ctx["object"].configuration
        ctx["target"] = ctx["object"].target
        ctx["target_type_display"] = ctx["target"].get_type_display()
        ctx["target_sha256"] = ctx["target"].sha256
        ctx["files"] = ctx["target"].files
        ctx["certificates"] = ctx["target"].certificates
        ctx['title'] = "Update santa rule"
        return ctx

    def form_valid(self, form):
        rule = form.save(commit=False)
        if rule.custom_msg != self.old_custom_msg:
            rule.version = F("version") + 1
        rule.save()
        form.save_m2m()
        return redirect(rule)


class DeleteConfigurationRuleView(LoginRequiredMixin, DeleteView):
    def get_object(self):
        return get_object_or_404(
            Rule.objects.select_related("configuration", "target"),
            pk=self.kwargs["pk"],
            configuration__pk=self.kwargs["configuration_pk"],
            ruleset__isnull=True
        )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['setup'] = True
        ctx['configuration'] = ctx["object"].configuration
        ctx['target'] = ctx["object"].target
        ctx['title'] = "Delete rule"
        return ctx

    def get_success_url(self):
        return reverse("santa:configuration_rules", args=(self.kwargs["configuration_pk"],))


class PickRuleBinaryView(LoginRequiredMixin, TemplateView):
    template_name = "santa/pick_rule_binary.html"

    def dispatch(self, request, *args, **kwargs):
        self.configuration = get_object_or_404(Configuration, pk=kwargs["configuration_pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["configuration"] = self.configuration
        form = BinarySearchForm(self.request.GET)
        form.is_valid()
        binaries = list(File.objects.search(**form.cleaned_data))
        existing_rules = {
            rule.target.sha256: rule
            for rule in Rule.objects.select_related("target")
                                    .filter(configuration=self.configuration,
                                            target__type=Target.BINARY,
                                            target__sha256__in=[binary.sha_256 for binary in binaries])
        }
        ctx['binaries'] = [(binary, existing_rules.get(binary.sha_256)) for binary in binaries]
        ctx['form'] = form
        return ctx


class PickRuleBundleView(LoginRequiredMixin, TemplateView):
    template_name = "santa/pick_rule_bundle.html"

    def dispatch(self, request, *args, **kwargs):
        self.configuration = get_object_or_404(Configuration, pk=kwargs["configuration_pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["configuration"] = self.configuration
        form = BundleSearchForm(self.request.GET)
        form.is_valid()
        bundles = list(Bundle.objects.search(**form.cleaned_data))
        existing_rules = {
            rule.target.sha256: rule
            for rule in Rule.objects.select_related("target")
                                    .filter(configuration=self.configuration,
                                            target__type=Target.BUNDLE,
                                            target__sha256__in=[bundle.target.sha256 for bundle in bundles])
        }
        ctx['bundles'] = [(bundle, existing_rules.get(bundle.target.sha256)) for bundle in bundles]
        ctx['form'] = form
        return ctx


class PickRuleCertificateView(LoginRequiredMixin, TemplateView):
    template_name = "santa/pick_rule_certificate.html"

    def dispatch(self, request, *args, **kwargs):
        self.configuration = get_object_or_404(Configuration, pk=kwargs["configuration_pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.configuration
        form = CertificateSearchForm(self.request.GET)
        form.is_valid()
        certificates = list(File.objects.search_certificates(**form.cleaned_data))
        existing_rules = {
            rule.target.sha256: rule
            for rule in Rule.objects.select_related("target")
                                    .filter(configuration=self.configuration,
                                            target__type=Target.CERTIFICATE,
                                            target__sha256__in=[certificate.sha_256 for certificate in certificates])
        }
        ctx['certificates'] = [(certificate, existing_rules.get(certificate.sha_256)) for certificate in certificates]
        ctx['form'] = form
        return ctx


# Sync API


class BaseSyncView(View):
    use_enrolled_machine_cache = True

    def _get_client_cert_dn(self):
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
            if request.META.get('HTTP_CONTENT_ENCODING', None) in ("zlib", "deflate"):
                payload = zlib.decompress(payload)
            return json.loads(payload)
        except ValueError:
            raise SuspiciousOperation("Could not read JSON data")

    def get_enrolled_machine(self):
        try:
            enrolled_machine = EnrolledMachine.objects.select_related(
                "enrollment__secret",
                "enrollment__configuration"
            ).get(
                enrollment__secret__secret=self.enrollment_secret_secret,
                hardware_uuid=self.hardware_uuid
            )
        except EnrolledMachine.DoesNotExist:
            pass
        else:
            if enrolled_machine.enrollment.configuration.client_certificate_auth and not self.client_cert_dn:
                raise PermissionDenied("Missing client certificate")
            return enrolled_machine

    def post(self, request, *args, **kwargs):
        # URL kwargs
        self.enrollment_secret_secret = kwargs["enrollment_secret"]
        try:
            self.hardware_uuid = str(UUID(kwargs["machine_id"]))
        except ValueError:
            raise PermissionDenied("Invalid machine id")

        self.client_cert_dn = self._get_client_cert_dn()

        self.user_agent, self.ip = user_agent_and_ip_address_from_request(request)

        self.request_data = self._get_json_data(request)

        self.cache_key = f"tests/santa/fixtures/{self.enrollment_secret_secret}{self.hardware_uuid}"
        self.enrolled_machine = None
        self.tag_ids = []
        if self.use_enrolled_machine_cache:
            try:
                self.enrolled_machine, self.tag_ids = cache.get(self.cache_key)
            except TypeError:
                pass
            else:
                if self.enrolled_machine.enrollment.configuration.client_certificate_auth and not self.client_cert_dn:
                    raise PermissionDenied("Missing client certificate")
        if not self.enrolled_machine:
            self.enrolled_machine = self.get_enrolled_machine()
            if not self.enrolled_machine:
                raise PermissionDenied("Machine not enrolled")
            meta_machine = MetaMachine(self.enrolled_machine.serial_number)
            self.tag_ids = [t.id for t in meta_machine.tags]
            cache.set(self.cache_key, (self.enrolled_machine, self.tag_ids), 600)  # TODO cache timeout hardcoded

        return JsonResponse(self.do_post())


class PreflightView(BaseSyncView):
    use_enrolled_machine_cache = False

    def _get_primary_user(self):
        # primary user
        primary_user = self.request_data.get('primary_user')
        if primary_user:
            primary_user = primary_user.strip()
            if primary_user:
                return primary_user
        return None

    def _get_enrolled_machine_defaults(self):
        defaults = {
            'serial_number': self.request_data['serial_num'],
            'santa_version': self.request_data['santa_version'],
            'primary_user': self._get_primary_user(),
            'client_mode': Configuration.MONITOR_MODE,
        }
        # client mode
        req_client_mode = self.request_data['client_mode']
        if req_client_mode == "LOCKDOWN":
            defaults['client_mode'] = Configuration.LOCKDOWN_MODE
        elif req_client_mode != "MONITOR":
            logger.error(f"Unknown client mode: {req_client_mode}")
        return defaults

    def _enroll_machine(self):
        try:
            enrollment = (Enrollment.objects.select_related("configuration", "secret")
                                    .get(secret__secret=self.enrollment_secret_secret))
        except Enrollment.DoesNotExist:
            raise PermissionDenied("Unknown enrollment secret")
        if enrollment.configuration.client_certificate_auth and not self.client_cert_dn:
            raise PermissionDenied("Missing client certificate")
        try:
            verify_enrollment_secret(
                "santa_enrollment", self.enrollment_secret_secret,
                self.user_agent, self.ip,
                serial_number=self.request_data["serial_num"],
                udid=self.hardware_uuid,
            )
        except EnrollmentSecretVerificationFailed:
            raise PermissionDenied("Wrong enrollment secret")

        # get or create enrolled machine
        enrolled_machine, _ = EnrolledMachine.objects.update_or_create(
            enrollment=enrollment,
            hardware_uuid=self.hardware_uuid,
            defaults=self._get_enrolled_machine_defaults(),
        )

        # apply enrollment secret tags
        for tag in enrollment.secret.tags.all():
            MachineTag.objects.get_or_create(serial_number=enrolled_machine.serial_number, tag=tag)

        # delete other enrolled machines
        other_enrolled_machines = (EnrolledMachine.objects.exclude(pk=enrolled_machine.pk)
                                                          .filter(hardware_uuid=self.hardware_uuid))
        if other_enrolled_machines.count():
            enrollment_action = 're-enrollment'
            other_enrolled_machines.delete()
        else:
            enrollment_action = 'enrollment'

        # post event
        post_enrollment_event(enrolled_machine.serial_number, self.user_agent, self.ip, {'action': enrollment_action})

        return enrolled_machine

    def get_enrolled_machine(self):
        enrolled_machine = super().get_enrolled_machine()
        if not enrolled_machine:
            enrolled_machine = self._enroll_machine()
        else:
            enrolled_machine_changed = False
            for attr, val in self._get_enrolled_machine_defaults().items():
                if getattr(enrolled_machine, attr) != val:
                    setattr(enrolled_machine, attr, val)
                    enrolled_machine_changed = True
            if enrolled_machine_changed:
                enrolled_machine.save()
        return enrolled_machine

    def _commit_machine_snapshot(self):
        # os version
        build = self.request_data["os_build"]
        os_version = dict(zip(('major', 'minor', 'patch'),
                              (int(s) for s in self.request_data['os_version'].split('.'))))
        os_version.update({'name': 'macOS', 'build': build})
        try:
            os_version.update(macos_version_from_build(build))
        except ValueError:
            pass

        # tree
        tree = {'source': {'module': 'zentral.contrib.santa',
                           'name': 'Santa'},
                'reference': self.hardware_uuid,
                'serial_number': self.enrolled_machine.serial_number,
                'os_version': os_version,
                'system_info': {'computer_name': self.request_data['hostname']},
                'public_ip_address': self.ip,
                }

        # tree primary user
        primary_user = self._get_primary_user()
        if primary_user:
            tree['principal_user'] = {
                'source': {'type': PrincipalUserSource.SANTA_MACHINE_OWNER},
                'unique_id': primary_user,
                'principal_name': primary_user,
            }

        # tree business unit
        business_unit = self.enrolled_machine.enrollment.secret.get_api_enrollment_business_unit()
        if business_unit:
            tree['business_unit'] = business_unit.serialize()

        commit_machine_snapshot_and_trigger_events(tree)

    def do_post(self):
        post_preflight_event(self.enrolled_machine.serial_number,
                             self.user_agent,
                             self.ip,
                             self.request_data)

        self._commit_machine_snapshot()

        response_dict = self.enrolled_machine.enrollment.configuration.get_sync_server_config(
            self.enrolled_machine.santa_version
        )

        # clean sync?
        enrolled_machine_rules = MachineRule.objects.filter(enrolled_machine=self.enrolled_machine)
        if self.request_data.get("request_clean_sync") is True:
            # clean sync requested, we wipe the existing machine rules
            enrolled_machine_rules.delete()
            response_dict["clean_sync"] = True
        elif not enrolled_machine_rules.count():
            # no existing machine rules, we tell santa it is a clean sync
            response_dict["clean_sync"] = True

        return response_dict


class RuleDownloadView(BaseSyncView):
    def do_post(self):
        request_cursor = self.request_data.get("cursor")
        rules, response_cursor = MachineRule.objects.get_next_rule_batch(
            self.enrolled_machine, self.tag_ids, request_cursor
        )
        response_dict = {"rules": rules}
        if response_cursor:
            # If a cursor is present in response, santa will make an extra request.
            # This is used to acknowlege the rules. There will be always one extra query to validate the last batch.
            # This is more robust than keeping the cursor on the enrolled machine and updating the cache to pass it
            # to the Postflight view to validate the last batch.
            response_dict["cursor"] = response_cursor
        return response_dict


class EventUploadView(BaseSyncView):
    def do_post(self):
        unknown_file_bundle_hashes = process_events(
            self.enrolled_machine,
            self.user_agent,
            self.ip,
            self.request_data
        )
        response_dict = {}
        if unknown_file_bundle_hashes:
            response_dict["event_upload_bundle_binaries"] = unknown_file_bundle_hashes
        return response_dict


class PostflightView(BaseSyncView):
    def do_post(self):
        cache.delete(self.cache_key)
        return {}
