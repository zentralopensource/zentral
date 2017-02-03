import os
import shutil
from zentral.utils.osx_package import PackageBuilder

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class SantaZentralEnrollPkgBuilder(PackageBuilder):
    MONITOR_MODE = 1
    LOCKDOWN_MODE = 2
    package_name = "zentral_santa_enroll.pkg"
    package_identifier = "io.zentral.santa_enroll"
    build_tmpl_dir = os.path.join(BASE_DIR, "build.tmpl")

    def include_tls_server_certs(self, config_plist, tls_server_certs):
        tls_server_certs_rel_path = "usr/local/zentral/tls_server_certs.crt"
        # copy crt in build dir
        shutil.copy(tls_server_certs,
                    self.get_root_path(tls_server_certs_rel_path))
        self.set_plist_keys(config_plist,
                            [("ServerAuthRootsFile",
                              "/{}".format(tls_server_certs_rel_path))])

    def extra_build_steps(self, tls_hostname, api_secret, tls_server_certs, mode=MONITOR_MODE,
                          blacklist_regex=None, whitelist_regex=None):
        if mode not in {self.MONITOR_MODE, self.LOCKDOWN_MODE}:
            raise ValueError("Unknown monitor mode {}".format(mode))
        if tls_server_certs and not os.path.exists(tls_server_certs):
            raise ValueError("tls_server_certs file {} is not readable".format(tls_server_certs))
        # extra steps
        config_plist = self.get_root_path("var/db/santa/config.plist")
        self.replace_in_file(config_plist,
                             (("%TLS_HOSTNAME%", tls_hostname),
                              ("%MODE%", str(mode))))
        postinstall_script = self.get_build_path("scripts", "postinstall")
        self.replace_in_file(postinstall_script,
                             (("%API_SECRET%", api_secret),
                              ("%TLS_HOSTNAME%", tls_hostname)))
        if tls_server_certs:
            self.include_tls_server_certs(config_plist, tls_server_certs)
        if blacklist_regex:
            self.set_plist_keys(config_plist, [("blacklist_regex", blacklist_regex)])
        if whitelist_regex:
            self.set_plist_keys(config_plist, [("whitelist_regex", whitelist_regex)])
