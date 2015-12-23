import plistlib
import os
import shutil
from zentral.utils.osx_package import PackageBuilder

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class SantaZentralEnrollPkgBuilder(PackageBuilder):
    package_name = "zentral_santa_enroll.pkg"
    build_tmpl_dir = os.path.join(BASE_DIR, "build.tmpl")

    def include_tls_server_certs(self, config_plist, tls_server_certs):
        tls_server_certs_rel_path = "usr/local/zentral/tls_server_certs.crt"
        # copy crt in build dir
        shutil.copy(tls_server_certs,
                    self.get_root_path(tls_server_certs_rel_path))
        # add config key
        with open(config_plist, "rb") as f:
            pl = plistlib.load(f)
        pl["ServerAuthRootsFile"] = "/{}".format(tls_server_certs_rel_path)
        with open(config_plist, "wb") as f:
            plistlib.dump(pl, f)

    def extra_build_steps(self, tls_hostname, api_secret, tls_server_certs):
        if tls_server_certs and not os.path.exists(tls_server_certs):
            raise ValueError("tls_server_certs file {} is not readable".format(tls_server_certs))
        # extra steps
        config_plist = self.get_root_path("var/db/santa/config.plist")
        self.replace_in_file(config_plist,
                             (("%TLS_HOSTNAME%", tls_hostname),
                              ("%MACHINE_ID%", api_secret)))
        if tls_server_certs:
            self.include_tls_server_certs(config_plist, tls_server_certs)
