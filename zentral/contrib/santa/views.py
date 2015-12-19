import json
import logging
import zlib
from django.core.urlresolvers import reverse
from django.http import JsonResponse, Http404
from django.views.generic import View, TemplateView
from zentral.core.stores import stores
from . import machine_id_secret, santa_conf, probes
from .events import post_santa_events, post_santa_preflight

logger = logging.getLogger('zentral.contrib.santa.views')


class IndexView(TemplateView):
    template_name = "santa/index.html"

    def get_context_data(self, **kwargs):
        context = super(IndexView, self).get_context_data(**kwargs)
        context['santa'] = True
        context['probes'] = probes
        return context


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


class SantaAPIError(Exception):
    pass


class BaseView(View):
    def do_post(self, data):
        raise NotImplementedError

    def _check_machine_id(self, machine_id):
        self.machine_id = machine_id
        try:
            secret, method, value = machine_id.split('$', 2)
        except ValueError:
            raise SantaAPIError('Malformed machine_id')
        if not secret == machine_id_secret:
            raise SantaAPIError('Invalid machine_id secret')
        if not method == 'SERIAL':
            raise SantaAPIError('Invalid machine_id secret method %s' % method)
        self.machine_serial_number = value

    def post(self, request, *args, **kwargs):
        self._check_machine_id(kwargs['machine_id'])
        self.user_agent = request.META.get("HTTP_USER_AGENT", "")
        self.ip = request.META.get("HTTP_X_REAL_IP", "")
        payload = request.body
        if not payload:
            data = None
        else:
            if request.META.get('HTTP_CONTENT_ENCODING', None) == 'zlib':
                payload = zlib.decompress(payload)
            payload = payload.decode('utf-8')
            data = json.loads(payload)
        return self.do_post(data)


class PreflightView(BaseView):
    def do_post(self, data):
        if self.machine_serial_number != data['serial_num']:
            raise SantaAPIError('Machine serial numbers do not match %s %s' % (self.machine_serial_number,
                                                                               data['serial_num']))
        post_santa_preflight(self.machine_serial_number,
                             self.user_agent,
                             self.ip,
                             data)
        response_d = {'BatchSize': 20,  # TODO: ???
                      'UploadLogsUrl': 'https://{host}{path}'.format(host=self.request.get_host(),
                                                                     path=reverse('santa:logupload',
                                                                                  args=(self.machine_id,)))}
        return JsonResponse(response_d)


class RuleDownloadView(BaseView):
    def do_post(self, data):
        return JsonResponse(santa_conf)


class EventUploadView(BaseView):
    def do_post(self, data):
        post_santa_events(self.machine_serial_number,
                          self.user_agent,
                          self.ip,
                          data)
        return JsonResponse({})


class LogUploadView(BaseView):
    pass


class PostflightView(BaseView):
    def do_post(self, data):
        return JsonResponse({})
