import os
from django.urls import reverse
from zentral.utils.osx_package import PackageBuilder
from zentral.contrib.santa.forms import EnrollmentForm
from zentral.contrib.santa.releases import Releases

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class SantaZentralEnrollPkgBuilder(PackageBuilder):
    name = "Zentral Santa Enrollment"
    package_name = "zentral_santa_enroll.pkg"
    base_package_identifier = "io.zentral.santa_enroll"
    build_tmpl_dir = os.path.join(BASE_DIR, "build.tmpl")
    form = EnrollmentForm
    standalone = True

    def __init__(self, enrollment, version=None):
        build_kwargs = {"release": enrollment.santa_release,
                        "version": "{}.0".format(version or enrollment.version),
                        "package_identifier_suffix": "pk-{}".format(enrollment.pk),
                        "enrollment_secret_secret": enrollment.secret.secret}
        business_unit = None
        mbu = enrollment.secret.meta_business_unit
        if mbu:
            try:
                business_unit = mbu.api_enrollment_business_units()[0]
            except IndexError:
                pass
        return super().__init__(business_unit, **build_kwargs)

    def get_product_archive_title(self):
        if self.build_kwargs.get("release"):
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
        enroll_script = self.get_root_path("usr", "local", "zentral", "santa", "enroll.py")
        self.replace_in_file(enroll_script,
                             (("%ENROLLMENT_URL%", "https://{}{}".format(self.get_tls_hostname(),
                                                                         reverse("santa:enroll"))),
                              ("%ENROLLMENT_SECRET%", self.build_kwargs["enrollment_secret_secret"])))
