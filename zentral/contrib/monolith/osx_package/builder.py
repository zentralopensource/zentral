import os
from django.urls import reverse
from zentral.utils.osx_package import EnrollmentPackageBuilder
from zentral.contrib.monolith.forms import EnrollmentForm
from zentral.contrib.monolith.releases import DEPNotifyReleases, MunkiReleases

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class MonolithZentralEnrollPkgBuilder(EnrollmentPackageBuilder):
    name = "Zentral Monolith Enrollment"
    package_name = "zentral_monolith_enroll.pkg"
    base_package_identifier = "io.zentral.monolith_enroll"
    build_tmpl_dir = os.path.join(BASE_DIR, "build.tmpl")
    form = EnrollmentForm
    standalone = True

    def __init__(self, enrollment, version=None):
        configuration = enrollment.configuration
        kwargs = {"release": enrollment.munki_release,
                  "no_restart": configuration.no_restart,
                  "depnotify_release": configuration.depnotify_release,
                  "depnotify_commands": configuration.depnotify_commands,
                  "eula": configuration.eula,
                  "setup_script": configuration.setup_script}
        super().__init__(enrollment, version, **kwargs)

    def get_product_archive(self):
        release = self.build_kwargs.get("release")
        if release:
            munki_releases = MunkiReleases()
            return munki_releases.get_requested_package(release)

    def get_extra_packages(self):
        depnotify_release = self.build_kwargs.get("depnotify_release")
        if depnotify_release:
            depnotify_releases = DEPNotifyReleases()
            yield depnotify_releases.get_requested_package(depnotify_release)

    def get_product_archive_title(self):
        return self.name

    def extra_build_steps(self):
        # setup script
        setup_script_path = ""
        setup_script = self.build_kwargs.get("setup_script")
        if setup_script:
            setup_script_path = "/usr/local/zentral/monolith/setup_script"
            self.create_file_with_content_string(setup_script_path[1:], setup_script, executable=True)

        # software_repo_url
        # TODO: hardcoded
        software_repo_url = "https://{}/monolith/munki_repo".format(self.get_tls_hostname())

        # enrollment url
        enrollment_url = "https://{}{}".format(self.get_tls_hostname(), reverse("monolith:enroll"))

        # depnotify
        depnotify_release = self.build_kwargs.get("depnotify_release")
        if depnotify_release:
            include_depnotify = 1
        else:
            include_depnotify = 0

        # depnotify / EULA
        eula = self.build_kwargs.get("eula")
        if eula:
            self.create_file_with_content_string("Users/Shared/eula.txt", eula)

        # postinstall script
        self.replace_in_file(self.get_build_path("scripts", "postinstall"),
                             (("%SETUP_SCRIPT_PATH%", setup_script_path),
                              ("%SOFTWARE_REPO_URL%", software_repo_url),
                              ("%ENROLLMENT_SECRET%", self.build_kwargs["enrollment_secret_secret"]),
                              ("%ENROLLMENT_URL%", enrollment_url),
                              ("%TLS_CA_CERT%", self.include_tls_ca_cert()),
                              ("%INCLUDE_DEPNOTIFY%", str(include_depnotify)),
                              ("%DEPNOTIFY_COMMANDS%", self.build_kwargs.get("depnotify_commands") or "")))

    def extra_product_archive_build_steps(self, pa_builder):
        no_restart = self.build_kwargs.get("no_restart")
        if no_restart:
            pa_builder.remove_pkg_ref_on_conclusion("com.googlecode.munki.launchd")
