import os
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
        # munki zentral postflight script
        postflight_script = self.get_root_path("usr/local/zentral/munki/zentral_postflight")
        replacements = [
            ("%TLS_HOSTNAME%", tls_hostname),
            ("%TLS_SERVER_CERTS%", self.include_tls_server_certs() or ""),
        ]
        self.replace_in_file(postflight_script, replacements)

        # postinstall script
        postinstall_script = self.get_build_path("scripts", "postinstall")
        replacements.extend([
            ("%ENROLLMENT_SECRET%", self.build_kwargs["enrollment_secret_secret"]),
            ("%ENROLLMENT_URL%", "https://{}{}".format(tls_hostname, reverse("munki:enroll")))
        ])
        self.replace_in_file(postinstall_script, replacements)
