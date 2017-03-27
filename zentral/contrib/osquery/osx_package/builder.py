import os
from django import forms
from django.utils.translation import ugettext_lazy as _
from zentral.utils.osx_package import EnrollmentForm, PackageBuilder
from zentral.contrib.osquery.releases import Releases

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class OsqueryEnrollmentForm(EnrollmentForm):
    release = forms.ChoiceField(
        label=_("Release"),
        choices=[],
        initial="",
        help_text="Choose an osquery release to be installed with the enrollment package.",
        required=False
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        release_field = self.fields["release"]
        if self.update_for:
            release_field.widget = forms.HiddenInput()
        else:
            choices = []
            if not self.standalone:
                choices.append(("", "Do not include osquery"))
            # TODO: Async or cached to not slow down the web page
            r = Releases()
            for filename, version, created_at, is_local in r.get_versions():
                choices.append((filename, filename))
            release_field.choices = choices

    def get_build_kwargs(self):
        kwargs = super().get_build_kwargs()
        if not self.update_for:
            kwargs["release"] = self.cleaned_data["release"]
        return kwargs


class OsqueryZentralEnrollPkgBuilder(PackageBuilder):
    standalone = True
    name = "Zentral Osquery Enrollment"
    form = OsqueryEnrollmentForm
    zentral_module = "zentral.contrib.osquery"
    package_name = "zentral_osquery_enroll.pkg"
    base_package_identifier = "io.zentral.osquery_enroll"
    build_tmpl_dir = os.path.join(BASE_DIR, "build.tmpl")

    def get_product_archive_title(self):
        if self.build_kwargs.get("release"):
            return self.build_kwargs.get("product_archive_title",
                                         self.name)

    def get_extra_packages(self):
        extra_packages = []
        release = self.build_kwargs.get("release")
        if release:
            r = Releases()
            extra_packages.append(r.get_requested_package(release))
        return extra_packages

    def extra_build_steps(self, **kwargs):
        launchd_plist = self.get_root_path("Library/LaunchDaemons/com.facebook.osqueryd.plist")
        # tls_hostname
        self.replace_in_file(launchd_plist,
                             (("%TLS_HOSTNAME%", self.get_tls_hostname()),))
        self.replace_in_file(self.get_build_path("scripts", "postinstall"),
                             (("%TLS_HOSTNAME%", self.get_tls_hostname()),))

        # tls_server_certs
        tls_server_certs_install_path = self.include_tls_server_certs()
        self.append_to_plist_key(launchd_plist,
                                 "ProgramArguments",
                                 "--tls_server_certs={}".format(tls_server_certs_install_path))
        # enroll secret secret
        self.replace_in_file(self.get_build_path("scripts", "preinstall"),
                             (("%ENROLL_SECRET_SECRET%", self.make_api_secret()),))
