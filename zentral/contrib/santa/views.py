import json
import logging
import zlib
from django.core.urlresolvers import reverse
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.generic import View, DetailView, ListView
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from . import machine_id_secret, santa_conf
from .events import post_santa_events, post_santa_preflight

logger = logging.getLogger('django_zentral.santa.views')


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
