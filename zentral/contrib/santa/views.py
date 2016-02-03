import logging
from django.core.urlresolvers import reverse
from django.http import Http404
from django.views.generic import TemplateView
from zentral.contrib.inventory.models import MachineSnapshot
from zentral.core.stores import stores
from zentral.utils.api_views import SignedRequestJSONPostAPIView, BaseEnrollmentView, BaseInstallerPackageView
from . import santa_conf, probes
from .events import post_santa_events, post_santa_preflight
from .osx_package.builder import SantaZentralEnrollPkgBuilder

logger = logging.getLogger('zentral.contrib.santa.views')


class ProbesView(TemplateView):
    template_name = "santa/probes.html"

    def get_context_data(self, **kwargs):
        context = super(ProbesView, self).get_context_data(**kwargs)
        context['santa'] = True
        context['probes'] = probes
        return context


class EnrollmentView(BaseEnrollmentView):
    template_name = "santa/enrollment.html"
    section = "santa"


class InstallerPackageView(BaseInstallerPackageView):
    module = "zentral.contrib.santa"
    builder = SantaZentralEnrollPkgBuilder


class ProbeView(TemplateView):
    template_name = "santa/probe.html"

    def get_context_data(self, **kwargs):
        context = super(ProbeView, self).get_context_data(**kwargs)
        context['santa'] = True

        # find probe
        # TODO log(1)
        probe = None
        for probe_name, probe_d in probes:
            if probe_name == kwargs['probe_key']:
                probe = probe_d
                break
        if not probe:
            raise Http404
        context['probe'] = probe

        # policies
        policies = []
        all_file_sha256 = []
        all_certificate_sha256 = []
        for idx, policy in enumerate(probe['santa']):
            # policy links. match policy sha256.
            policy_links = []
            sha256 = policy['sha256']
            if policy['rule_type'] == 'CERTIFICATE':
                search_dict = {'signing_chain.sha256': [sha256]}
                all_certificate_sha256.append(sha256)
            else:
                search_dict = {'file_sha256': [sha256]}
                all_file_sha256.append(sha256)
            for store in stores:
                # match
                url = store.get_visu_url(search_dict)
                if url:
                    policy_links.append((store.name, url))
            policy_links.sort()
            policies.append((policy, policy_links))
        context['santa_policies'] = policies

        # probe links. match all sha256 in the probe.
        probe_links = []
        probe_search_dict = {}
        if all_file_sha256:
            probe_search_dict['file_sha256'] = all_file_sha256
        if all_certificate_sha256:
            probe_search_dict['all_certificate_sha256'] = all_certificate_sha256
        if probe_search_dict:
            for store in stores:
                url = store.get_visu_url(probe_search_dict)
                if url:
                    probe_links.append((store.name, url))
        probe_links.sort()
        context['probe_links'] = probe_links
        return context

# API


class BaseView(SignedRequestJSONPostAPIView):
    verify_module = "zentral.contrib.santa"

    def get_request_secret(self, request, *args, **kwargs):
        self.machine_id = kwargs['machine_id']
        return self.machine_id


class PreflightView(BaseView):
    def do_post(self, data):
        machine_serial_number = data['serial_num']
        post_santa_preflight(machine_serial_number,
                             self.user_agent,
                             self.ip,
                             data)
        major, minor, patch = (int(s) for s in data['os_version'].split('.'))
        tree = {'source': {'module': 'zentral.contrib.santa',
                           'name': 'Santa',
                           },
                'reference': self.machine_id,
                'machine': {'serial_number': machine_serial_number},
                'os_version': {'name': 'Mac OS X',
                               'major': major,
                               'minor': minor,
                               'patch': patch,
                               'build': data['os_build'],
                               },
                'system_info': {'computer_name': data['hostname']},
                }
        if self.business_unit:
            tree['business_unit'] = self.business_unit.serialize()
        ms, created = MachineSnapshot.objects.commit(tree)
        return {'BatchSize': 20,  # TODO: ???
                'UploadLogsUrl': 'https://{host}{path}'.format(host=self.request.get_host(),
                                                               path=reverse('santa:logupload',
                                                                            args=(self.machine_id,)))}


class RuleDownloadView(BaseView):
    def do_post(self, data):
        return santa_conf


class EventUploadView(BaseView):
    def do_post(self, data):
        try:
            ms = MachineSnapshot.objects.current().get(source__module='zentral.contrib.santa',
                                                       reference=self.machine_id)
        except MachineSnapshot.DoesNotExist:
            machine_serial_number = "UNKNOWN"
            logger.error("Machine ID not found", extra={'request': self.request})
        else:
            machine_serial_number = ms.machine.serial_number
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
