import json
import logging
from dateutil import parser
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import SuspiciousOperation
from django.db import transaction
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils.crypto import get_random_string
from django.views.generic import FormView, ListView, TemplateView, View
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.contrib.inventory.models import MachineTag
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events, verify_enrollment_secret
from zentral.core.events.base import post_machine_conflict_event
from zentral.core.probes.models import ProbeSource
from zentral.utils.api_views import APIAuthError, JSONPostAPIView, SignedRequestHeaderJSONPostAPIView, verify_secret
from zentral.utils.http import user_agent_and_ip_address_from_request
from .events import post_munki_enrollment_event, post_munki_events, post_munki_request_event
from .forms import CreateInstallProbeForm, EnrollmentForm, UpdateInstallProbeForm
from .models import EnrolledMachine, Enrollment, MunkiState
from .osx_package.builder import MunkiZentralEnrollPkgBuilder
from .utils import prepare_ms_tree_certificates

logger = logging.getLogger('zentral.contrib.munki.views')


# enrollment


class EnrollmentListView(LoginRequiredMixin, ListView):
    model = Enrollment

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["enrollments_count"] = ctx["object_list"].count()
        return ctx


class CreateEnrollmentView(LoginRequiredMixin, TemplateView):
    template_name = "munki/enrollment_form.html"

    def get_forms(self):
        secret_form_kwargs = {"prefix": "secret"}
        enrollment_form_kwargs = {}
        if self.request.method == "POST":
            secret_form_kwargs["data"] = self.request.POST
            enrollment_form_kwargs["data"] = self.request.POST
        return (EnrollmentSecretForm(**secret_form_kwargs),
                EnrollmentForm(**enrollment_form_kwargs))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
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
        enrollment = get_object_or_404(Enrollment, pk=kwargs["pk"])
        builder = MunkiZentralEnrollPkgBuilder(enrollment)
        return builder.build_and_make_response()


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


# install probe


class CreateInstallProbeView(LoginRequiredMixin, FormView):
    form_class = CreateInstallProbeForm
    template_name = "core/probes/form.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['title'] = 'Create munki install probe'
        ctx['probes'] = True
        return ctx

    def form_valid(self, form):
        probe_source = form.save()
        return HttpResponseRedirect(probe_source.get_absolute_url())


class UpdateInstallProbeView(LoginRequiredMixin, FormView):
    form_class = UpdateInstallProbeForm
    template_name = "core/probes/form.html"

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


class BaseView(JSONPostAPIView):
    enrollment = None

    def get_enrolled_machine_token(self, request):
        # new way
        authorization_header = request.META.get("HTTP_AUTHORIZATION")
        if not authorization_header:
            return None
        if "MunkiEnrolledMachine" not in authorization_header:
            raise APIAuthError("Wrong authorization token")
        return authorization_header.replace("MunkiEnrolledMachine", "").strip()

    def verify_enrolled_machine_token(self, token):
        try:
            enrolled_machine = (EnrolledMachine.objects.select_related("enrollment__secret__meta_business_unit")
                                                       .get(token=token))
        except EnrolledMachine.DoesNotExist:
            raise APIAuthError("Enrolled machine does not exist")
        else:
            self.enrollment = enrolled_machine.enrollment
            self.machine_serial_number = enrolled_machine.serial_number
            self.business_unit = self.enrollment.secret.get_api_enrollment_business_unit()

    def get_request_secret(self, request):
        # old way
        # TODO: deprecate and remove
        return request.META.get(SignedRequestHeaderJSONPostAPIView.api_secret_header_key)

    def verify_request_secret(self, secret):
        data = verify_secret(secret, "zentral.contrib.munki")
        self.machine_serial_number = data.get('machine_serial_number', None)
        self.business_unit = data.get('business_unit', None)

    def check_request_secret(self, request, *args, **kwargs):
        enrolled_machine_token = self.get_enrolled_machine_token(request)
        if enrolled_machine_token:
            # new way
            self.request_secret = enrolled_machine_token
            self.verify_enrolled_machine_token(enrolled_machine_token)
        else:
            # old way
            self.request_secret = self.get_request_secret(request)
            if self.request_secret:
                self.verify_request_secret(self.request_secret)
            else:
                raise APIAuthError("Could not authenticate the request")


class JobDetailsView(BaseView):
    def check_data_secret(self, data):
        if not self.machine_serial_number:
            logger.error("No machine serial number. Request secret %s", self.request_secret)
            return
        msn = data['machine_serial_number']
        if not msn:
            logger.error("No reported machine serial number. Request secret %s", self.request_secret)
            return
        if msn != self.machine_serial_number:
            # the serial number reported by the zentral postflight is not the one in the enrollment secret.
            auth_err = "Zentral postflight reported SN {} different from enrollment SN {}".format(
                msn, self.machine_serial_number
            )
            post_machine_conflict_event(self.request, "zentral.contrib.munki", msn, self.machine_serial_number, {})
            raise APIAuthError(auth_err)

    def do_post(self, data):
        event_data = {"request_type": "job_details"}
        if self.enrollment:
            event_data["enrollment"] = {"pk": self.enrollment.pk}
        post_munki_request_event(self.machine_serial_number, self.user_agent, self.ip, **event_data)
        response_d = {}
        try:
            munki_state = MunkiState.objects.get(machine_serial_number=self.machine_serial_number)
        except MunkiState.DoesNotExist:
            pass
        else:
            response_d['last_seen_sha1sum'] = munki_state.sha1sum
        return response_d


class PostJobView(BaseView):
    @transaction.non_atomic_requests
    def do_post(self, data):
        # commit machine snapshot
        ms_tree = data['machine_snapshot']
        ms_tree['source'] = {'module': 'zentral.contrib.munki',
                             'name': 'Munki'}
        machine = ms_tree.pop('machine', None)
        if machine:
            # TODO deprecated
            ms_tree['serial_number'] = machine['serial_number']
        ms_tree['reference'] = ms_tree['serial_number']
        ms_tree['public_ip_address'] = self.ip
        if self.business_unit:
            ms_tree['business_unit'] = self.business_unit.serialize()
        prepare_ms_tree_certificates(ms_tree)
        ms = commit_machine_snapshot_and_trigger_events(ms_tree)
        if not ms:
            raise RuntimeError("Could not commit machine snapshot")

        msn = ms.serial_number

        # reports
        reports = [(parser.parse(r.pop('start_time')),
                    parser.parse(r.pop('end_time')),
                    r) for r in data.pop('reports')]
        # events
        event_data = {"request_type": "postflight"}
        if self.enrollment:
            event_data["enrollment"] = {"pk": self.enrollment.pk}
        post_munki_request_event(msn, self.user_agent, self.ip, **event_data)
        post_munki_events(msn,
                          self.user_agent,
                          self.ip,
                          (r for _, _, r in reports))

        # MunkiState
        update_dict = {'user_agent': self.user_agent,
                       'ip': self.ip}
        if reports:
            reports.sort()
            start_time, end_time, report = reports[-1]
            update_dict.update({'munki_version': report.get('munki_version', None),
                                'sha1sum': report['sha1sum'],
                                'run_type': report['run_type'],
                                'start_time': start_time,
                                'end_time': end_time})
        with transaction.atomic():
            MunkiState.objects.update_or_create(machine_serial_number=msn,
                                                defaults=update_dict)
        return {}
