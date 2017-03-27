import os
from zentral.utils.osx_package import EnrollmentForm, PackageBuilder

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class MunkiZentralEnrollPkgBuilder(PackageBuilder):
    name = "Zentral Munki Enrollment"
    form = EnrollmentForm
    zentral_module = "zentral.contrib.munki"
    package_name = "zentral_munki_enroll.pkg"
    base_package_identifier = "io.zentral.munki_enroll"
    build_tmpl_dir = os.path.join(BASE_DIR, "build.tmpl")

    def extra_build_steps(self):
        # munki zentral postflight script
        patterns = [("%TLS_HOSTNAME%", self.get_tls_hostname()),
                    ("%API_SECRET%", self.make_api_secret())]
        tls_server_certs_install_path = self.include_tls_server_certs()
        patterns.append(("%TLS_SERVER_CERTS%", tls_server_certs_install_path))
        postflight_script = self.get_root_path("usr/local/zentral/munki/zentral_postflight")
        self.replace_in_file(postflight_script, patterns)
        # postinstall script
        postinstall_script = self.get_build_path("scripts", "postinstall")
        self.replace_in_file(postinstall_script, (("%TLS_HOSTNAME%", self.get_tls_hostname()),))
