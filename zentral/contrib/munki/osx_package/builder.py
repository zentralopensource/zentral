import os
import shutil
from zentral.utils.osx_package import PackageBuilder

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class MunkiZentralEnrollPkgBuilder(PackageBuilder):
    package_name = "zentral_munki_enroll.pkg"
    build_tmpl_dir = os.path.join(BASE_DIR, "build.tmpl")

    def include_tls_server_certs(self, tls_server_certs):
        tls_server_certs_rel_path = "usr/local/zentral/tls_server_certs.crt"
        # copy crt in build dir
        shutil.copy(tls_server_certs,
                    self.get_root_path(tls_server_certs_rel_path))
        return "/{}".format(tls_server_certs_rel_path)

    def extra_build_steps(self, tls_hostname, api_secret, tls_server_certs):
        patterns = [("%TLS_HOSTNAME%", tls_hostname),
                    ("%API_SECRET%", api_secret)]
        if tls_server_certs:
            if not os.path.exists(tls_server_certs):
                raise ValueError("tls_server_certs file {} is not readable".format(tls_server_certs))
            tls_server_certs_install_path = self.include_tls_server_certs(tls_server_certs)
        else:
            tls_server_certs_install_path = ""
        patterns.append(("%TLS_SERVER_CERTS%", tls_server_certs_install_path))
        postflight_script = self.get_root_path("usr/local/zentral/munki/postflight")
        self.replace_in_file(postflight_script, patterns)
