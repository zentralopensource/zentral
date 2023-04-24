from datetime import datetime, timedelta
import json
import logging
from dateutil import parser
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core.cache import cache
from django.core.exceptions import SuspiciousOperation
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.utils.crypto import get_random_string
from django.utils.timezone import is_aware, make_naive
from django.views.generic import CreateView, DeleteView, DetailView, FormView, ListView, TemplateView, UpdateView, View
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.contrib.inventory.models import MachineTag, MetaMachine
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events, verify_enrollment_secret
from zentral.core.events.base import post_machine_conflict_event
from zentral.core.probes.models import ProbeSource
from zentral.utils.api_views import APIAuthError, JSONPostAPIView
from zentral.utils.http import user_agent_and_ip_address_from_request
from zentral.utils.json import remove_null_character
from zentral.utils.terraform import build_config_response
from .events import post_munki_enrollment_event, post_munki_events, post_munki_request_event
from .forms import CreateInstallProbeForm, ConfigurationForm, EnrollmentForm, UpdateInstallProbeForm
from .models import (Configuration, EnrolledMachine, Enrollment, ManagedInstall, MunkiState,
                     PrincipalUserDetectionSource)
from .terraform import iter_resources
from .utils import apply_managed_installs, prepare_ms_tree_certificates, update_managed_install_with_event

logger = logging.getLogger('zentral.contrib.munki.views')


# configuration


class ConfigurationListView(PermissionRequiredMixin, ListView):
    permission_required = "munki.view_configuration"
    model = Configuration

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration_count"] = ctx["object_list"].count()
        return ctx


class TerraformExportView(PermissionRequiredMixin, View):
    permission_required = (
        "munki.view_configuration",
        "munki.view_enrollment",
    )

    def get(self, request, *args, **kwargs):
        return build_config_response(iter_resources(), "terraform_munki")


class CreateConfigurationView(PermissionRequiredMixin, CreateView):
    permission_required = "munki.add_configuration"
    model = Configuration
    form_class = ConfigurationForm


class ConfigurationView(PermissionRequiredMixin, DetailView):
    permission_required = "munki.view_configuration"
    model = Configuration

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        # principal user detection sources
        ctx["principal_user_detection_sources"] = ", ".join(
            sorted(PrincipalUserDetectionSource[src].value for src in self.object.principal_user_detection_sources)
        )
        # enrollments
        enrollments = []
        enrollment_count = 0
        for enrollment in self.object.enrollment_set.select_related("secret").all().order_by("pk"):
            enrollment_count += 1
            distributor = None
            distributor_link = False
            dct = enrollment.distributor_content_type
            if dct:
                distributor = enrollment.distributor
                if self.request.user.has_perm(f"{dct.app_label}.view_{dct.model}"):
                    distributor_link = True
            enrollments.append((enrollment, distributor, distributor_link))
        ctx["enrollments"] = enrollments
        ctx["enrollment_count"] = enrollment_count
        return ctx


class UpdateConfigurationView(PermissionRequiredMixin, UpdateView):
    permission_required = "munki.change_configuration"
    model = Configuration
    form_class = ConfigurationForm


# enrollment


class CreateEnrollmentView(PermissionRequiredMixin, TemplateView):
    permission_required = "munki.add_enrollment"
    template_name = "munki/enrollment_form.html"

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
        enrollment.configuration = self.configuration
        enrollment.save()
        return redirect(enrollment)

    def post(self, request, *args, **kwargs):
        secret_form, enrollment_form = self.get_forms()
        if secret_form.is_valid() and enrollment_form.is_valid():
            return self.forms_valid(secret_form, enrollment_form)
        else:
            return self.forms_invalid(secret_form, enrollment_form)


class DeleteEnrollmentView(PermissionRequiredMixin, DeleteView):
    permission_required = "munki.delete_enrollment"

    def get_queryset(self):
        return (Enrollment.objects.select_related("configuration")
                                  .filter(configuration__pk=self.kwargs["configuration_pk"],
                                          distributor_content_type__isnull=True,
                                          distributor_pk__isnull=True))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.object.configuration
        ctx["enrolled_machine_count"] = self.object.enrolledmachine_set.count()
        return ctx

    def get_success_url(self):
        return self.object.configuration.get_absolute_url()


class EnrollmentBumpVersionView(PermissionRequiredMixin, TemplateView):
    permission_required = "munki.change_enrollment"
    template_name = "munki/enrollment_confirm_version_bump.html"

    def dispatch(self, request, *args, **kwargs):
        self.enrollment = get_object_or_404(
            Enrollment,
            pk=kwargs["pk"],
            configuration__pk=kwargs["configuration_pk"],
            distributor_content_type__isnull=True,
            distributor_pk__isnull=True,
        )
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["enrollment"] = self.enrollment
        return ctx

    def post(self, request, *args, **kwargs):
        self.enrollment.save()  # will bump the version
        return redirect(self.enrollment)


# install probe


class CreateInstallProbeView(PermissionRequiredMixin, FormView):
    permission_required = "probes.add_probesource"
    form_class = CreateInstallProbeForm
    template_name = "probes/form.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['title'] = 'Create munki install probe'
        ctx['probes'] = True
        return ctx

    def form_valid(self, form):
        probe_source = form.save()
        return redirect(probe_source)


class UpdateInstallProbeView(PermissionRequiredMixin, FormView):
    permission_required = "probes.change_probesource"
    form_class = UpdateInstallProbeForm
    template_name = "probes/form.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs['probe_id'])
        self.probe = self.probe_source.load()
        return super().dispatch(request, *args, **kwargs)

    def get_initial(self):
        return self.form_class.get_probe_initial(self.probe)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['title'] = 'Update munki install probe'
        ctx["probes"] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['cancel_url'] = self.probe_source.get_absolute_url("munki")
        return ctx

    def form_valid(self, form):
        body = form.get_body()

        def func(probe_d):
            probe_d.update(body)
            if "unattended_installs" not in body:
                probe_d.pop("unattended_installs", None)
        self.probe_source.update_body(func)
        return super().form_valid(form)

    def get_success_url(self):
        return self.probe_source.get_absolute_url("munki")


# API


class EnrollView(View):
    def post(self, request, *args, **kwargs):
        user_agent, ip = user_agent_and_ip_address_from_request(request)
        try:
            request_json = json.loads(request.body.decode("utf-8"))
            secret = request_json["secret"]
            serial_number = request_json["serial_number"]
            uuid = request_json["uuid"]
            es_request = verify_enrollment_secret(
                "munki_enrollment", secret,
                user_agent, ip,
                serial_number, uuid
            )
        except (KeyError, ValueError, EnrollmentSecretVerificationFailed):
            raise SuspiciousOperation
        else:
            # get or create enrolled machine
            enrolled_machine, enrolled_machine_created = EnrolledMachine.objects.get_or_create(
                enrollment=es_request.enrollment_secret.munki_enrollment,
                serial_number=serial_number,
                defaults={"token": get_random_string(64)}
            )

            # apply enrollment secret tags
            for tag in es_request.enrollment_secret.tags.all():
                MachineTag.objects.get_or_create(serial_number=serial_number, tag=tag)

            # post event
            post_munki_enrollment_event(serial_number, user_agent, ip,
                                        {'action': "enrollment" if enrolled_machine_created else "re-enrollment"})
            return JsonResponse({"token": enrolled_machine.token})


class BaseView(JSONPostAPIView):
    def get_enrolled_machine_token(self, request):
        authorization_header = request.META.get("HTTP_AUTHORIZATION")
        if not authorization_header:
            raise APIAuthError("Missing or empty Authorization header")
        if "MunkiEnrolledMachine" not in authorization_header:
            raise APIAuthError("Wrong authorization token")
        return authorization_header.replace("MunkiEnrolledMachine", "").strip()

    def verify_enrolled_machine_token(self, token):
        cache_key = f"munki.{token}"
        try:
            self.enrollment, self.machine_serial_number, self.business_unit = cache.get(cache_key)
        except TypeError:
            try:
                enrolled_machine = (EnrolledMachine.objects.select_related("enrollment__configuration",
                                                                           "enrollment__secret__meta_business_unit")
                                                           .get(token=token))
            except EnrolledMachine.DoesNotExist:
                raise APIAuthError("Enrolled machine does not exist")
            else:
                self.enrollment = enrolled_machine.enrollment
                self.machine_serial_number = enrolled_machine.serial_number
                self.business_unit = self.enrollment.secret.get_api_enrollment_business_unit()
            cache.set(cache_key, (self.enrollment, self.machine_serial_number, self.business_unit), timeout=600)

    def check_request_secret(self, request, *args, **kwargs):
        enrolled_machine_token = self.get_enrolled_machine_token(request)
        self.verify_enrolled_machine_token(enrolled_machine_token)


class JobDetailsView(BaseView):
    def check_data_secret(self, data):
        msn = data.get('machine_serial_number')
        if not msn:
            raise APIAuthError(
                f"No reported machine serial number. Request SN {self.machine_serial_number}."
            )
        if msn != self.machine_serial_number:
            # the serial number reported by the zentral postflight is not the one in the enrollment secret.
            auth_err = "Zentral postflight reported SN {} different from enrollment SN {}".format(
                msn, self.machine_serial_number
            )
            post_machine_conflict_event(self.request, "zentral.contrib.munki", msn, self.machine_serial_number, {})
            raise APIAuthError(auth_err)

    def do_post(self, data):
        post_munki_request_event(
            self.machine_serial_number,
            self.user_agent, self.ip,
            request_type="job_details",
            enrollment={"pk": self.enrollment.pk}
        )

        # serialize configuration
        configuration = self.enrollment.configuration
        response_d = {"apps_full_info_shard": configuration.inventory_apps_full_info_shard}
        if configuration.principal_user_detection_sources:
            principal_user_detection = response_d.setdefault("principal_user_detection", {})
            principal_user_detection["sources"] = configuration.principal_user_detection_sources
            if configuration.principal_user_detection_domains:
                principal_user_detection["domains"] = configuration.principal_user_detection_domains
        if configuration.collected_condition_keys:
            response_d["collected_condition_keys"] = configuration.collected_condition_keys

        # add tags
        # TODO better cache for the machine tags
        m = MetaMachine(self.machine_serial_number)
        response_d["incidents"] = [mi.incident.name for mi in m.open_incidents()]
        response_d["tags"] = m.tag_names()

        # last seen sha1sum
        # last managed installs sync
        try:
            munki_state = MunkiState.objects.get(machine_serial_number=self.machine_serial_number)
        except MunkiState.DoesNotExist:
            pass
        else:
            response_d['last_seen_sha1sum'] = munki_state.sha1sum
            response_d['managed_installs'] = (
                munki_state.last_managed_installs_sync is None
                or (
                    datetime.utcnow() - munki_state.last_managed_installs_sync
                    > timedelta(days=configuration.managed_installs_sync_interval_days)
                )
            )
        return response_d


class PostJobView(BaseView):
    def do_post(self, data):
        # lock enrolled machine
        EnrolledMachine.objects.select_for_update().filter(serial_number=self.machine_serial_number)

        # commit machine snapshot
        ms_tree = data['machine_snapshot']
        ms_tree['source'] = {'module': 'zentral.contrib.munki',
                             'name': 'Munki'}
        ms_tree['reference'] = ms_tree['serial_number']
        ms_tree['public_ip_address'] = self.ip
        if self.business_unit:
            ms_tree['business_unit'] = self.business_unit.serialize()
        prepare_ms_tree_certificates(ms_tree)
        extra_facts = ms_tree.pop("extra_facts", None)
        if isinstance(extra_facts, dict):
            ms_tree["extra_facts"] = remove_null_character(extra_facts)
        # cleanup profiles
        reported_profiles = ms_tree.pop("profiles", None)
        if reported_profiles:
            profiles = []
            for profile in reported_profiles:
                if profile not in profiles:
                    profiles.append(profile)
                else:
                    logger.error("Duplicated profile %s for machine %s.",
                                 profile.get("uuid", "UNKNOWN UUID"), self.machine_serial_number)
            ms_tree["profiles"] = profiles
        # cleanup OS version
        if "os_version" in ms_tree:
            if ms_tree["os_version"].get("patch") is None:
                ms_tree["os_version"]["patch"] = 0
        ms = commit_machine_snapshot_and_trigger_events(ms_tree)
        if not ms:
            raise RuntimeError(f"Could not commit machine {self.machine_serial_number} snapshot")

        # delete all managed installs if last seen report not found
        # which is a good indicator that the machine has been wiped
        last_seen_report_found = data.get("last_seen_report_found")
        if last_seen_report_found is not None and not last_seen_report_found:
            ManagedInstall.objects.filter(machine_serial_number=self.machine_serial_number).delete()

        # prepare reports
        reports = []
        report_count = event_count = 0
        for r in data.pop('reports'):
            report_count += 1
            event_count += len(r.get("events", []))
            reports.append((
                parser.parse(r.pop('start_time')),
                parser.parse(r.pop('end_time')),
                r
            ))
        reports.sort()

        munki_request_event_kwargs = {
            "request_type": "postflight",
            "enrollment": {"pk": self.enrollment.pk},
            "report_count": report_count,
            "event_count": event_count,
        }
        if last_seen_report_found is not None:
            munki_request_event_kwargs["last_seen_report_found"] = last_seen_report_found

        # update machine managed installs
        managed_installs = data.get("managed_installs")
        if managed_installs is not None:
            munki_request_event_kwargs["managed_installs"] = True
            munki_request_event_kwargs["managed_install_count"] = len(managed_installs)
            # update managed installs using the complete list
            incident_updates = apply_managed_installs(
                self.machine_serial_number, managed_installs,
                self.enrollment.configuration
            )
            # incident updates are attached to the munki request event
            if incident_updates:
                munki_request_event_kwargs["incident_updates"] = incident_updates
        else:
            munki_request_event_kwargs["managed_installs"] = False
            # update managed installs using the install and removal events in the reports
            for _, _, report in reports:
                for created_at, event in report.get("events", []):
                    # time
                    event_time = parser.parse(created_at)
                    if is_aware(event_time):
                        event_time = make_naive(event_time)
                    for incident_update in update_managed_install_with_event(
                        self.machine_serial_number, event, event_time,
                        self.enrollment.configuration
                    ):
                        # incident updates are attached to each munki event
                        event.setdefault("incident_updates", []).append(incident_update)

        # update machine munki state
        update_dict = {'user_agent': self.user_agent,
                       'ip': self.ip}
        if managed_installs is not None:
            update_dict["last_managed_installs_sync"] = datetime.utcnow()
        if reports:
            start_time, end_time, report = reports[-1]
            update_dict.update({'munki_version': report.get('munki_version', None),
                                'sha1sum': report['sha1sum'],
                                'run_type': report['run_type'],
                                'start_time': start_time,
                                'end_time': end_time})
        MunkiState.objects.update_or_create(machine_serial_number=self.machine_serial_number,
                                            defaults=update_dict)

        # events
        post_munki_request_event(
            self.machine_serial_number,
            self.user_agent, self.ip,
            **munki_request_event_kwargs
        )

        post_munki_events(
            self.machine_serial_number,
            self.user_agent, self.ip,
            (r for _, _, r in reports)
        )

        return {}
