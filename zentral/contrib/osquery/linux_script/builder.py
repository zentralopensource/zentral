import os
from django.http import HttpResponse
from zentral.utils.osx_package import APIConfigToolsMixin
from zentral.contrib.osquery.forms import EnrollmentForm


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class OsqueryZentralEnrollScriptBuilder(APIConfigToolsMixin):
    form = EnrollmentForm
    script_name = "zentral_osquery_setup.sh"

    def __init__(self, enrollment):
        self.business_unit = enrollment.secret.get_api_enrollment_business_unit()
        self.build_kwargs = {
            "enrollment_secret_secret": enrollment.secret.secret,
            "release": enrollment.osquery_release,
            "serialized_flags": enrollment.configuration.get_serialized_flag_list(),
        }

    def build_and_make_response(self):
        template_path = os.path.join(BASE_DIR, "template.sh")
        with open(template_path, "r") as f:
            content = f.read()

        # tls hostname
        content = content.replace("%TLS_HOSTNAME%", self.get_tls_hostname())

        serialized_flags = self.build_kwargs["serialized_flags"]

        # tls server certs
        tls_fullchain = self.get_tls_fullchain()
        if tls_fullchain:
            content = content.replace("%INCLUDE_TLS_SERVER_CERTS%", "true")
            content = content.replace("%TLS_SERVER_CERTS%", tls_fullchain)
            serialized_flags.append("--tls_server_certs=/etc/zentral/tls_server_certs.crt")
        else:
            content = content.replace("%INCLUDE_TLS_SERVER_CERTS%", "false")

        # enrollment secret
        content = content.replace("%ENROLL_SECRET_SECRET%", self.build_kwargs["enrollment_secret_secret"])

        # extra flags
        content = content.replace("%EXTRA_FLAGS%", "\n".join(serialized_flags))

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
