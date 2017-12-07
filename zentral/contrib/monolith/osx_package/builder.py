import os
from django import forms
from django.utils.translation import ugettext_lazy as _
from zentral.utils.osx_package import EnrollmentForm, PackageBuilder
from zentral.contrib.monolith.releases import Releases

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class MonolithEnrollmentForm(EnrollmentForm):
    release = forms.ChoiceField(
        label=_("Release"),
        choices=[],
        initial="",
        help_text="Choose a munki release to be installed with the enrollment package.",
        required=False
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        choices = []
        if not self.standalone:
            choices.append(("", "Do not include munki"))
        # TODO: Async or cached to not slow down the web page
        r = Releases()
        for filename, version, created_at, download_url, is_local in r.get_versions():
            choices.append((filename, filename))
        self.fields["release"].choices = choices

    def get_build_kwargs(self):
        kwargs = super().get_build_kwargs()
        kwargs["release"] = self.cleaned_data["release"]
        return kwargs


class MunkiMonolithConfigPkgBuilder(PackageBuilder):
    standalone = True
    name = "Munki Monolith Enrollment"
    form = MonolithEnrollmentForm
    zentral_module = "zentral.contrib.monolith"
    package_name = "munki_monolith_config.pkg"
    base_package_identifier = "io.zentral.munki_monolith_config"
    build_tmpl_dir = os.path.join(BASE_DIR, "build.tmpl")

    def get_product_archive(self):
        release = self.build_kwargs.get("release")
        if release:
            r = Releases()
            return r.get_requested_package(release)

    def get_product_archive_title(self):
        if self.build_kwargs.get("release"):
            return self.build_kwargs.get("product_archive_title", self.name)

    def extra_build_steps(self, **kwargs):
        postinstall_script = self.get_build_path("scripts", "postinstall")
        # software_repo_url
        # TODO: hardcoded
        software_repo_url = "https://{}/monolith/munki_repo".format(self.get_tls_hostname())
        self.replace_in_file(postinstall_script,
                             (("%SOFTWARE_REPO_URL%", software_repo_url),))
        # headers
        headers = {"X-Monolith-Token": self.make_api_secret(),
                   "X-Zentral-Serial-Number": "${MSN}"}
        headers_str = " ".join('"%s: %s"' % (k, v) for k, v in headers.items())
        self.replace_in_file(postinstall_script,
                             (("%HEADERS%", headers_str),))
        # tls_server_certs
        tls_ca_cert_install_path = self.include_tls_ca_cert()
        self.replace_in_file(postinstall_script,
                             (("%TLS_CA_CERT%", tls_ca_cert_install_path),))
