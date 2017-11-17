import os
from django import forms
from django.core.validators import MinValueValidator, MaxValueValidator
from django.urls import reverse
from django.utils.translation import ugettext_lazy as _
from zentral.utils.osx_package import EnrollmentForm, PackageBuilder
from zentral.contrib.osquery.releases import Releases

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class OsqueryEnrollmentForm(EnrollmentForm):
    buffered_log_max = forms.IntegerField(
        label=_("Max. buffered log"),
        initial=0,
        validators=[MinValueValidator(0), MaxValueValidator(1000000)],
        help_text=("Maximum number of logs (status and result) "
                   "kept on disk if Zentral is unavailable "
                   "(0 = unlimited, max 1000000)"),
        required=True
    )
    disable_carver = forms.BooleanField(
        label=_("Disable file carver"),
        initial=True,
        required=False
    )
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

    def clean_disable_carver(self):
        try:
            disable_carver = bool(self.cleaned_data["disable_carver"])
        except (ValueError, TypeError):
            disable_carver = True
        return disable_carver

    def clean_release(self):
        release = self.cleaned_data["release"]
        if release:
            r = Releases()
            try:
                r.get_requested_package(release)
            except:
                raise forms.ValidationError("Could not download osquery package.")
        return release

    def get_build_kwargs(self):
        kwargs = super().get_build_kwargs()
        kwargs["buffered_log_max"] = self.cleaned_data["buffered_log_max"]
        kwargs["disable_carver"] = self.cleaned_data["disable_carver"]
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

        extra_prog_args = []

        # tls_server_certs
        tls_server_certs_install_path = self.include_tls_server_certs()
        extra_prog_args.append("--tls_server_certs={}".format(tls_server_certs_install_path))

        # buffered log max
        buffered_log_max = kwargs.get("buffered_log_max", 0)
        if buffered_log_max:
            extra_prog_args.append("--buffered_log_max={}".format(buffered_log_max))

        # file carver
        disable_carver = kwargs.get("disable_carver", True)
        extra_prog_args.append("--disable_carver={}".format(str(disable_carver).lower()))
        if not disable_carver:
            extra_prog_args.append("--carver_start_endpoint={}".format(reverse('osquery:carver_start')))
            extra_prog_args.append("--carver_continue_endpoint={}".format(reverse('osquery:carver_continue')))

        self.append_to_plist_key(launchd_plist, "ProgramArguments", extra_prog_args)

        # enroll secret secret
        self.replace_in_file(self.get_build_path("scripts", "preinstall"),
                             (("%ENROLL_SECRET_SECRET%", self.make_api_secret()),))
