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

        # tls server certs
        with open(self.get_tls_server_certs(), "r") as f:
            tls_server_certs_data = f.read()
            content = content.replace("%TLS_SERVER_CERTS%", tls_server_certs_data)

        # enrollment secret
        content = content.replace("%ENROLL_SECRET_SECRET%", self.make_api_secret())

        extra_flags = []

        # buffered log max
        buffered_log_max = self.build_kwargs.get("buffered_log_max", 0)
        if buffered_log_max:
            extra_flags.append("--buffered_log_max={}".format(buffered_log_max))

        # file carver
        disable_carver = self.build_kwargs.get("disable_carver", True)
        extra_flags.append("--disable_carver={}".format(str(disable_carver).lower()))
        if not disable_carver:
            extra_flags.append("--carver_start_endpoint={}".format(reverse('osquery:carver_start')))
            extra_flags.append("--carver_continue_endpoint={}".format(reverse('osquery:carver_continue')))

        content = content.replace("%EXTRA_FLAGS%", "\n".join(extra_flags))

        # only config or install + config
        # TODO: we can't pin it to a known osquery version if we configure the repos
        # not really coherent with the form
        release = self.build_kwargs.get("release")
        install_osquery = release > ""
        content = content.replace("%INSTALL_OSQUERY%", str(install_osquery).lower())

        response = HttpResponse(content, "text/x-shellscript")
        response['Content-Length'] = len(content)
        response['Content-Disposition'] = 'attachment; filename="{}"'.format(self.script_name)
        return response
