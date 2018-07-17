import os
from django.urls import reverse
from zentral.utils.osx_package import EnrollmentPackageBuilder
from zentral.contrib.santa.forms import EnrollmentForm
from zentral.contrib.santa.releases import Releases

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class SantaZentralEnrollPkgBuilder(EnrollmentPackageBuilder):
    name = "Zentral Santa Enrollment"
    package_name = "zentral_santa_enroll.pkg"
    base_package_identifier = "io.zentral.santa_enroll"
    build_tmpl_dir = os.path.join(BASE_DIR, "build.tmpl")
    form = EnrollmentForm
    standalone = True

    def __init__(self, enrollment, version=None):
        super().__init__(enrollment, version,
                         release=enrollment.santa_release)

    def get_product_archive_title(self):
        return self.name

    def get_extra_packages(self):
        extra_packages = []
        release = self.build_kwargs.get("release")
        if release:
            r = Releases()
            extra_packages.append(r.get_requested_package(release))
        return extra_packages

    def extra_build_steps(self):
        self.include_tls_server_certs()
        tls_hostname = self.get_tls_hostname()
        postinstall_script = self.get_build_path("scripts", "postinstall")
        self.replace_in_file(postinstall_script,
                             (("%TLS_HOSTNAME%", tls_hostname),))
        enroll_script = self.get_root_path("usr", "local", "zentral", "santa", "enroll.py")
        self.replace_in_file(enroll_script,
                             (("%ENROLLMENT_URL%", "https://{}{}".format(tls_hostname,
                                                                         reverse("santa:enroll"))),
                              ("%ENROLLMENT_SECRET%", self.build_kwargs["enrollment_secret_secret"])))
