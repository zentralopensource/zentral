import logging
from datetime import timedelta
from dateutil import parser
from django.utils import timezone
from django.views.generic import View, TemplateView
from zentral.conf import settings
from zentral.contrib.inventory.models import MachineSnapshot
from zentral.utils.api_views import SignedRequestHeaderJSONPostAPIView, make_secret
from .events import post_munki_events
from .models import MunkiState
from .osx_package.builder import MunkiZentralEnrollPkgBuilder

logger = logging.getLogger('zentral.contrib.munki.views')


class ProbesView(TemplateView):
    template_name = "munki/probes.html"

    def get_context_data(self, **kwargs):
        context = super(ProbesView, self).get_context_data(**kwargs)
        context['munki'] = True
        context['probes'] = []  # TODO
        return context


class EnrollmentView(TemplateView):
    template_name = "munki/enrollment.html"

    def get_context_data(self, **kwargs):
        context = super(EnrollmentView, self).get_context_data(**kwargs)
        context['munki'] = True
        return context


class InstallerPackageView(View):
    def post(self, request):
        try:
            tls_server_certs = settings['api']['tls_server_certs']
        except KeyError:
            tls_server_certs = None
        builder = MunkiZentralEnrollPkgBuilder()
        return builder.build_and_make_response(request.get_host(),
                                               make_secret("zentral.contrib.munki"),
                                               tls_server_certs)


class BaseView(SignedRequestHeaderJSONPostAPIView):
    verify_module = "zentral.contrib.munki"


class JobDetailsView(BaseView):
    max_fileinfo_age = timedelta(hours=1)

    def do_post(self, data):
        msn = data['machine_serial_number']
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
    def do_post(self, data):
        ms_tree = data['machine_snapshot']
        ms_tree['source'] = {'module': 'zentral.contrib.munki',
                             'name': 'Munki'}
        ms_tree['reference'] = ms_tree['machine']['serial_number']
        if data.get('include_santa_fileinfo', False):
            clean_certs_datetime(ms_tree)
            ms, created = MachineSnapshot.objects.commit(ms_tree)
            msn = ms.machine.serial_number
        else:
            msn = ms_tree['reference']
        reports = [(parser.parse(r.pop('start_time')),
                    parser.parse(r.pop('end_time')),
                    r) for r in data.pop('reports')]
        # Events
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
        MunkiState.objects.update_or_create(machine_serial_number=msn,
                                            defaults=update_dict)
        return {}
