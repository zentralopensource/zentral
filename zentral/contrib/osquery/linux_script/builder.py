import os
from django.http import HttpResponse
from django.urls import reverse
from zentral.utils.osx_package import APIConfigToolsMixin
from zentral.contrib.osquery.osx_package.builder import OsqueryEnrollmentForm

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class OsqueryZentralEnrollScriptBuilder(APIConfigToolsMixin):
    form = OsqueryEnrollmentForm
    zentral_module = "zentral.contrib.osquery"
    script_name = "osquery_zentral_setup.sh"

    def __init__(self, business_unit, **kwargs):
        self.business_unit = business_unit
        self.build_kwargs = kwargs

    def build_and_make_response(self):
        template_path = os.path.join(BASE_DIR, "template.sh")
        with open(template_path, "r") as f:
            content = f.read()
        # tls hostname
        content = content.replace("%TLS_HOSTNAME%", self.get_tls_hostname())
        # enrollment secret
        content = content.replace("%ENROLL_SECRET_SECRET%", self.make_api_secret())
        # file carver
        disable_carver = self.build_kwargs.get("disable_carver", True)
        carver_flags = ["--disable_carver={}".format(str(disable_carver).lower())]
        if not disable_carver:
            carver_flags.append("--carver_start_endpoint={}".format(reverse('osquery:carver_start')))
            carver_flags.append("--carver_continue_endpoint={}".format(reverse('osquery:carver_continue')))
        content = content.replace("%CARVER_FLAGS%", "\n".join(carver_flags))
        # only config or install + config
        # TODO: we can't pin it to a known osquery version if we configure the repos
        # not really coherent with the form
        release = self.build_kwargs.get("release")
        install_osquery = release > ""
        content = content.replace("%INSTALL_OSQUERY%", str(install_osquery).lower())
        with open(self.get_tls_server_certs(), "r") as f:
            tls_server_certs_data = f.read()
            content = content.replace("%TLS_SERVER_CERTS%", tls_server_certs_data)
        response = HttpResponse(content, "text/x-shellscript")
        response['Content-Length'] = len(content)
        response['Content-Disposition'] = 'attachment; filename="{}"'.format(self.script_name)
        return response
