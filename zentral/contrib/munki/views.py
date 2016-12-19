import logging
from datetime import timedelta
from dateutil import parser
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.generic.edit import FormView
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events
from zentral.core.probes.models import ProbeSource
from zentral.utils.api_views import SignedRequestHeaderJSONPostAPIView, BaseEnrollmentView, BaseInstallerPackageView
from .events import post_munki_events, post_munki_request_event
from .forms import CreateInstallProbeForm, UpdateInstallProbeForm
from .models import MunkiState
from .osx_package.builder import MunkiZentralEnrollPkgBuilder

logger = logging.getLogger('zentral.contrib.munki.views')


class EnrollmentView(LoginRequiredMixin, BaseEnrollmentView):
    template_name = "munki/enrollment.html"


class InstallerPackageView(LoginRequiredMixin, BaseInstallerPackageView):
    module = "zentral.contrib.munki"
    builder = MunkiZentralEnrollPkgBuilder


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


class BaseView(SignedRequestHeaderJSONPostAPIView):
    verify_module = "zentral.contrib.munki"


class JobDetailsView(BaseView):
    max_fileinfo_age = timedelta(hours=1)

    def do_post(self, data):
        msn = data['machine_serial_number']
        post_munki_request_event(msn, self.user_agent, self.ip, request_type="job_details")
        response_d = {'include_santa_fileinfo': True}
        try:
            munki_state = MunkiState.objects.get(machine_serial_number=msn)
        except MunkiState.DoesNotExist:
            pass
        else:
            response_d['last_seen_sha1sum'] = munki_state.sha1sum
            if munki_state.binaryinfo_last_seen:
                last_fileinfo_age = timezone.now() - munki_state.binaryinfo_last_seen
                response_d['include_santa_fileinfo'] = last_fileinfo_age >= self.max_fileinfo_age
        return response_d


def clean_certs_datetime(tree):
    for k, v in tree.items():
        if k == 'valid_from' or k == 'valid_until':
            tree[k] = parser.parse(v)
        elif isinstance(v, list):
            for d in v:
                clean_certs_datetime(d)
        elif isinstance(v, dict):
            clean_certs_datetime(v)


class PostJobView(BaseView):
    @transaction.non_atomic_requests
    def do_post(self, data):
        ms_tree = data['machine_snapshot']
        ms_tree['source'] = {'module': 'zentral.contrib.munki',
                             'name': 'Munki'}
        machine = ms_tree.pop('machine', None)
        if machine:
            # TODO deprecated
            ms_tree['serial_number'] = machine['serial_number']
        ms_tree['reference'] = ms_tree['serial_number']
        ms_tree['public_ip_address'] = self.ip
        if data.get('include_santa_fileinfo', False):
            clean_certs_datetime(ms_tree)
            if self.business_unit:
                ms_tree['business_unit'] = self.business_unit.serialize()
            ms = commit_machine_snapshot_and_trigger_events(ms_tree)
            if not ms:
                raise RuntimeError("Could not commit machine snapshot")
            msn = ms.serial_number
        else:
            msn = ms_tree['reference']
        reports = [(parser.parse(r.pop('start_time')),
                    parser.parse(r.pop('end_time')),
                    r) for r in data.pop('reports')]
        # Events
        post_munki_request_event(msn, self.user_agent, self.ip,
                                 request_type="postflight",
                                 include_santa_fileinfo=data.get('include_santa_fileinfo', False))
        post_munki_events(msn,
                          self.user_agent,
                          self.ip,
                          (r for _, _, r in reports))
        # MunkiState
        update_dict = {'user_agent': self.user_agent,
                       'ip': self.ip}
        if data.get('santa_fileinfo_included', False):
            update_dict['binaryinfo_last_seen'] = timezone.now()
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
