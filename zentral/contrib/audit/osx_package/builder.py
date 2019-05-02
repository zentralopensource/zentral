import os
import shutil
import yaml
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
        # filebeat binary
        r = Releases()
        local_path = r.get_requested_package(self.build_kwargs["release"])
        filebeat_path = self.get_root_path("usr/local/zentral/bin/filebeat")
        filebeat_dir = os.path.dirname(filebeat_path)
        if not os.path.exists(filebeat_dir):
            os.makedirs(filebeat_dir)
        shutil.copy(local_path, self.get_root_path("usr/local/zentral/bin/filebeat"))

        # filebeat config
        tls_server_certs_install_path = self.include_tls_server_certs()
        certificate_authorities = []
        if tls_server_certs_install_path:
            certificate_authorities.append(tls_server_certs_install_path)
        filebeat_cfg_path = self.get_root_path("usr/local/zentral/audit/filebeat.yml")
        with open(filebeat_cfg_path, "r") as filebeat_cfg_f:
            filebeat_cfg = yaml.load(filebeat_cfg_f)
        filebeat_cfg["output"] = {
            "logstash": {
                "hosts": ["{}:5044".format(self.get_tls_hostname())],
                "ssl": {
                    "certificate_authorities": certificate_authorities,
                    "certificate": self.build_kwargs["client_certificate_path"],
                    "key": self.build_kwargs["client_certificate_key_path"]
                }
            }
        }
        with open(filebeat_cfg_path, "w") as filebeat_cfg_f:
            filebeat_cfg_f.write(yaml.dump(filebeat_cfg))

        # postinstall
        postinstall_script = self.get_build_path("scripts", "postinstall")
        self.replace_in_file(postinstall_script,
                             (("%TLS_HOSTNAME%", self.get_tls_hostname()),))
