import os
import shutil
from zentral.utils.osx_package import PackageBuilder
from zentral.utils.filebeat_releases import Releases

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class AuditZentralShipperPkgBuilder(PackageBuilder):
    standalone = False
    name = "Zentral Audit Shipper"
    package_name = "zentral_audit_shipper.pkg"
    base_package_identifier = "io.zentral.audit_shipper"
    build_tmpl_dir = os.path.join(BASE_DIR, "build.tmpl")

    def extra_build_steps(self):
        r = Releases()
        local_path = r.get_requested_package(self.build_kwargs["release"])
        filebeat_path = self.get_root_path("usr/local/zentral/bin/filebeat")
        filebeat_dir = os.path.dirname(filebeat_path)
        if not os.path.exists(filebeat_dir):
            os.makedirs(filebeat_dir)
        shutil.copy(local_path, self.get_root_path("usr/local/zentral/bin/filebeat"))
        tls_server_certs_install_path = self.include_tls_server_certs()
        filebeat_config = self.get_root_path("usr/local/zentral/audit/filebeat.yml")
        self.replace_in_file(filebeat_config,
                             (("%TLS_HOSTNAME%", self.get_tls_hostname()),
                              ("%TLS_SERVER_CERTS%", tls_server_certs_install_path),
                              ("%TLS_CLIENT_CERT%", self.build_kwargs["client_certificate_path"]),
                              ("%TLS_CLIENT_CERT_KEY%", self.build_kwargs["client_certificate_key_path"])))
        postinstall_script = self.get_build_path("scripts", "postinstall")
        self.replace_in_file(postinstall_script,
                             (("%TLS_HOSTNAME%", self.get_tls_hostname()),))
