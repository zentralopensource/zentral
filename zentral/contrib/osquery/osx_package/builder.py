import os
import plistlib
from zentral.utils.osx_package import EnrollmentPackageBuilder
from zentral.contrib.osquery.forms import EnrollmentForm
from zentral.contrib.osquery.releases import get_osquery_local_asset

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class OsqueryZentralEnrollPkgBuilder(EnrollmentPackageBuilder):
    name = "Zentral Osquery Enrollment"
    package_name = "zentral_osquery_enroll.pkg"
    base_package_identifier = "com.zentral.osquery_enroll"
    build_tmpl_dir = os.path.join(BASE_DIR, "build.tmpl")
    form = EnrollmentForm
    standalone = True
    local_subfolder = "osquery"

    def __init__(self, enrollment, version=None):
        super().__init__(enrollment, version,
                         release=enrollment.osquery_release,
                         serialized_flags=enrollment.configuration.get_serialized_flags())

    def get_product_archive_title(self):
        if self.build_kwargs.get("release"):
            return self.name

    def get_extra_packages(self):
        extra_packages = []
        release = self.build_kwargs.get("release")
        if release:
            extra_packages.append(get_osquery_local_asset(release, ".pkg"))
        return extra_packages

    def extra_build_steps(self):
        # enroll secret secret in preinstall
        self.replace_in_file(self.get_build_path("scripts", "preinstall"),
                             (("%ENROLL_SECRET_SECRET%", self.build_kwargs["enrollment_secret_secret"]),))

        # tls_hostname in postinstall
        tls_hostname = self.get_tls_hostname()
        hostname_replacement = (("%TLS_HOSTNAME%", tls_hostname),)
        self.replace_in_file(self.get_build_path("scripts", "postinstall"), hostname_replacement)

        # Extra flags
        extra_flags = self.build_kwargs["serialized_flags"]

        # include the certs and point to them in the ProgramArguments if necessary
        tls_server_certs_install_path = self.include_tls_server_certs()
        if tls_server_certs_install_path:
            extra_flags.append("--tls_server_certs={}".format(tls_server_certs_install_path))

        self.replace_in_file(self.get_root_path("usr/local/zentral/osquery/flagfile.txt"),
                             (("%EXTRA_FLAGS%", "\n".join(extra_flags)),))

        # add enrollment info plist
        with open(self.get_root_path(f"usr/local/zentral/{self.local_subfolder}/enrollment.plist"), "wb") as f:
            plistlib.dump({"enrollment": {"id": self.enrollment.pk,
                                          "version": self.enrollment.version},
                           "fqdn": tls_hostname}, f)
