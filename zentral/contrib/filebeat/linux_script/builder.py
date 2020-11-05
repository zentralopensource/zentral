import io
import os
from django.http import FileResponse
from zentral.utils.osx_package import APIConfigToolsMixin


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class ZentralFilebeatEnrollmentScriptBuilder(APIConfigToolsMixin):
    script_name_tmpl = "{}-filebeat_enrollment.py"

    def __init__(self, enrollment):
        self.business_unit = enrollment.secret.get_api_enrollment_business_unit()
        self.enrollment_secret = enrollment.secret.secret
        self.filebeat_release = enrollment.filebeat_release

    def build_and_make_response(self):
        template_path = os.path.join(BASE_DIR, "template.py")
        with open(template_path, "r") as f:
            content = f.read()

        # tls hostname
        tls_hostname = self.get_tls_hostname()
        content = content.replace("%TLS_HOSTNAME%", tls_hostname)
        content = content.replace("%TLS_HOSTNAME_FOR_CLIENT_CERT_AUTH%",
                                  self.get_tls_hostname(for_client_cert_auth=True))

        # tls server certs
        tls_fullchain = self.get_tls_fullchain()
        content = content.replace("%TLS_SERVER_CERTS%", tls_fullchain or "")

        # enrollment secret
        content = content.replace("%ENROLLMENT_SECRET%", self.enrollment_secret)

        # filebeat release
        content = content.replace("%FILEBEAT_VERSION%", self.filebeat_release)

        return FileResponse(
            io.BytesIO(content.encode("utf-8")), content_type="text/x-python",
            as_attachment=True,
            filename=self.script_name_tmpl.format(tls_hostname)
        )
