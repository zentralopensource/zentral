import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.urlresolvers import reverse
from django.http import HttpResponse
from django.views.generic import View
from zentral.conf import settings
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.utils.api_views import make_secret, BaseEnrollmentView, BaseInstallerPackageView
from zentral.contrib.osquery.osx_package.builder import OsqueryZentralEnrollPkgBuilder
from zentral.contrib.osquery.deb_script.builder import OsqueryZentralEnrollScriptBuilder

logger = logging.getLogger('zentral.contrib.osquery.views.setup')


class EnrollmentView(LoginRequiredMixin, BaseEnrollmentView):
    builder = OsqueryZentralEnrollPkgBuilder
    template_name = "osquery/enrollment.html"


class EnrollmentDebuggingView(LoginRequiredMixin, View):
    debugging_template = """machine_serial_number="0123456789"
enroll_secret="%(secret)s\$SERIAL\$$machine_serial_number"
node_key_json=$(curl -XPOST -k -d '{"enroll_secret":"'"$enroll_secret"'"}' %(tls_hostname)s%(enroll_path)s)
echo $node_key_json | jq .
curl -XPOST -k -d "$node_key_json"  %(tls_hostname)s%(config_path)s | jq ."""

    def get(self, request, *args, **kwargs):
        try:
            mbu = MetaBusinessUnit.objects.get(pk=int(request.GET['mbu_id']))
            # -> BaseInstallerPackageView
            # TODO Race. The meta_business_unit could maybe be without any api BU.
            # TODO. Better selection if multiple BU ?
            bu = mbu.api_enrollment_business_units()[0]
        except (KeyError, ValueError):
            bu = None
        debugging_tools = self.debugging_template % {'config_path': reverse("osquery:config"),
                                                     'enroll_path': reverse("osquery:enroll"),
                                                     'secret': make_secret("zentral.contrib.osquery", bu),
                                                     'tls_hostname': settings['api']['tls_hostname']}
        return HttpResponse(debugging_tools)


class InstallerPackageView(LoginRequiredMixin, BaseInstallerPackageView):
    builder = OsqueryZentralEnrollPkgBuilder
    module = "zentral.contrib.osquery"
    template_name = "osquery/enrollment.html"


class SetupScriptView(LoginRequiredMixin, BaseInstallerPackageView):
    builder = OsqueryZentralEnrollScriptBuilder
    module = "zentral.contrib.osquery"
    template_name = "osquery/enrollment.html"
