import logging
from django.core.urlresolvers import reverse
from django.http import HttpResponse
from django.views.generic import TemplateView, View
from zentral.conf import settings
from zentral.contrib.inventory.models import MachineSnapshot, MetaBusinessUnit, MetaMachine
from zentral.core.probes.conf import ProbeList
from zentral.utils.api_views import (make_secret,
                                     SignedRequestJSONPostAPIView, BaseEnrollmentView, BaseInstallerPackageView)
from .conf import build_santa_conf
from .events import post_santa_events, post_santa_preflight
from .osx_package.builder import SantaZentralEnrollPkgBuilder
from .probes import SantaProbe

logger = logging.getLogger('zentral.contrib.santa.views')


class ProbesView(TemplateView):
    template_name = "santa/probes.html"

    def get_context_data(self, **kwargs):
        context = super(ProbesView, self).get_context_data(**kwargs)
        context['santa'] = True
        pl = ProbeList()  # not all_probes to avoid cache inconsistency
        context['probes'] = pl.class_filter(SantaProbe)
        context['event_type_probes'] = pl.module_prefix_filter("santa").exclude_class(SantaProbe)
        return context


class EnrollmentView(BaseEnrollmentView):
    template_name = "santa/enrollment.html"
    section = "santa"


class EnrollmentDebuggingView(View):
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
        except ValueError:
            bu = None
        secret = make_secret("zentral.contrib.santa", bu)
        debugging_tools = self.debugging_template % {'secret': secret,
                                                     'tls_hostname': settings['api']['tls_hostname']}
        return HttpResponse(debugging_tools)


class InstallerPackageView(BaseInstallerPackageView):
    module = "zentral.contrib.santa"
    builder = SantaZentralEnrollPkgBuilder


# API


class BaseView(SignedRequestJSONPostAPIView):
    verify_module = "zentral.contrib.santa"

    def get_request_secret(self, request, *args, **kwargs):
        self.machine_id = kwargs['machine_id']
        return self.machine_id


class PreflightView(BaseView):
    def do_post(self, data):
        machine_serial_number = data['serial_num']
        assert(machine_serial_number == self.machine_serial_number)
        post_santa_preflight(machine_serial_number,
                             self.user_agent,
                             self.ip,
                             data)
        major, minor, patch = (int(s) for s in data['os_version'].split('.'))
        tree = {'source': {'module': 'zentral.contrib.santa',
                           'name': 'Santa',
                           },
                'reference': machine_serial_number,
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
