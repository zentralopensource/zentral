import os
from django.http import HttpResponse
from zentral.utils.osx_package import EnrollmentForm, APIConfigToolsMixin

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class OsqueryZentralEnrollScriptBuilder(APIConfigToolsMixin):
    form = EnrollmentForm
    zentral_module = "zentral.contrib.osquery"
    script_name = "osquery_zentral_setup.sh"

    def __init__(self, business_unit, **kwargs):
        self.business_unit = business_unit

    def build_and_make_response(self):
        template_path = os.path.join(BASE_DIR, "template.sh")
        with open(template_path, "r") as f:
            content = f.read()
        content = content.replace("%TLS_HOSTNAME%", self.get_tls_hostname())
        content = content.replace("%ENROLL_SECRET_SECRET%", self.make_api_secret())
        with open(self.get_tls_server_certs(), "r") as f:
            tls_server_certs_data = f.read()
            content = content.replace("%TLS_SERVER_CERTS%", tls_server_certs_data)
        response = HttpResponse(content, "text/x-shellscript")
        response['Content-Length'] = len(content)
        response['Content-Disposition'] = 'attachment; filename="{}"'.format(self.script_name)
        return response
