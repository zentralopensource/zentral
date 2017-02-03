import os
import shutil
from zentral.utils.osx_package import PackageBuilder

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class OsqueryZentralEnrollPkgBuilder(PackageBuilder):
    package_name = "zentral_osquery_enroll.pkg"
    package_identifier = "io.zentral.osquery_enroll"
    build_tmpl_dir = os.path.join(BASE_DIR, "build.tmpl")

    def set_tls_hostname(self):
        self.replace_in_file(self.launchd_plist,
                             (("%TLS_HOSTNAME%", self.tls_hostname),))
        self.replace_in_file(self.postinstall,
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
        self.append_to_plist_key(self.launchd_plist,
                                 "ProgramArguments",
                                 "--tls_server_certs=/{}".format(tls_server_certs_rel_path))

    def extra_build_steps(self, tls_hostname, enroll_secret_secret, tls_server_certs):
        # extra args
        self.tls_hostname = tls_hostname
        self.enroll_secret_secret = enroll_secret_secret
        if tls_server_certs and not os.path.exists(tls_server_certs):
            raise ValueError("tls_server_certs file {} is not readable".format(tls_server_certs))
        self.tls_server_certs = tls_server_certs
        # extra steps
        self.launchd_plist = self.get_root_path("Library/LaunchDaemons/com.facebook.osqueryd.plist")
        self.postinstall = self.get_build_path("scripts", "postinstall")
        self.set_enroll_secret_secret()
        self.set_tls_hostname()
        if self.tls_server_certs:
            self.include_tls_server_certs()
