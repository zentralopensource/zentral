import os
import plistlib
from django.urls import reverse
from zentral.contrib.munki.forms import EnrollmentForm
from zentral.utils.osx_package import EnrollmentPackageBuilder

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class MunkiZentralEnrollPkgBuilder(EnrollmentPackageBuilder):
    name = "Zentral Munki Enrollment"
    form = EnrollmentForm
    package_name = "zentral_munki_enroll.pkg"
    base_package_identifier = "io.zentral.munki_enroll"
    build_tmpl_dir = os.path.join(BASE_DIR, "build.tmpl")

    def extra_build_steps(self):
        tls_hostname = self.get_tls_hostname()
        # munki zentral preflight and postflight script
        replacements = [
            ("%TLS_HOSTNAME%", tls_hostname),
            ("%TLS_SERVER_CERTS%", self.include_tls_server_certs() or ""),
        ]
        for phase in ("preflight", "postflight"):
            script_path = self.get_root_path(f"usr/local/zentral/munki/zentral_{phase}")
            self.replace_in_file(script_path, replacements)

        # postinstall script
        postinstall_script = self.get_build_path("scripts", "postinstall")
        replacements.extend([
            ("%ENROLLMENT_SECRET%", self.build_kwargs["enrollment_secret_secret"]),
            ("%ENROLLMENT_URL%", "https://{}{}".format(tls_hostname, reverse("munki_public:enroll"))),
            ("%HAS_DISTRIBUTOR%", "YES" if self.build_kwargs.get("has_distributor") else "NO"),
        ])
        self.replace_in_file(postinstall_script, replacements)

        # add enrollment info plist
        with open(self.get_root_path("usr/local/zentral/munki/enrollment.plist"), "wb") as f:
            plistlib.dump({"enrollment": {"id": self.enrollment.pk,
                                          "version": self.enrollment.version},
                           "fqdn": tls_hostname}, f)
