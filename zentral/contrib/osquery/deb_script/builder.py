import os
from django.http import HttpResponse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class OsqueryZentralEnrollScriptBuilder(object):
    script_name = "osquery_zentral_setup.sh"

    def build_and_make_response(self, business_unit, tls_hostname, enroll_secret_secret, tls_server_certs):
        template_path = os.path.join(BASE_DIR, "template.sh")
        with open(template_path, "r") as f:
            content = f.read()
        content = content.replace("%TLS_HOSTNAME%", tls_hostname)
        content = content.replace("%ENROLL_SECRET_SECRET%", enroll_secret_secret)
        with open(tls_server_certs, "r") as f:
            tls_server_certs_data = f.read()
            content = content.replace("%TLS_SERVER_CERTS%", tls_server_certs_data)
        response = HttpResponse(content, "application/octet-stream")
        response['Content-Length'] = len(content)
        response['Content-Disposition'] = 'attachment; filename="{}"'.format(self.script_name)
        return response
