import plistlib
import os
import shutil
from zentral.utils.osx_package import PackageBuilder

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class OsqueryZentralEnrollPkgBuilder(PackageBuilder):
    package_name = "zentral_osquery_enroll.pkg"
    build_tmpl_dir = os.path.join(BASE_DIR, "build.tmpl")

    def set_tls_hostname(self):
        self.replace_in_file(self.launchd_plist,
                             (("%TLS_HOSTNAME%", self.tls_hostname),))

    def set_enroll_secret_secret(self):
        self.replace_in_file(self.get_build_path("scripts", "preinstall"),
                             (("%ENROLL_SECRET_SECRET%", self.enroll_secret_secret),))

    def include_tls_server_certs(self):
        tls_server_certs_rel_path = "usr/local/zentral/tls_server_certs.crt"
        # copy crt in build dir
        shutil.copy(self.tls_server_certs,
                    self.get_root_path(tls_server_certs_rel_path))
        # add command line option
        with open(self.launchd_plist, "rb") as f:
            pl = plistlib.load(f)
        pl["ProgramArguments"].append("--tls_server_certs=/{}".format(tls_server_certs_rel_path))
        with open(self.launchd_plist, "wb") as f:
            plistlib.dump(pl, f)

    def extra_build_steps(self, tls_hostname, enroll_secret_secret, tls_server_certs):
        # extra args
        self.tls_hostname = tls_hostname
        self.enroll_secret_secret = enroll_secret_secret
        if tls_server_certs and not os.path.exists(tls_server_certs):
            raise ValueError("tls_server_certs file {} is not readable".format(tls_server_certs))
        self.tls_server_certs = tls_server_certs
        # extra steps
        self.launchd_plist = self.get_root_path("Library/LaunchDaemons/com.facebook.osqueryd.plist")
        self.set_enroll_secret_secret()
        self.set_tls_hostname()
        if self.tls_server_certs:
            self.include_tls_server_certs()
