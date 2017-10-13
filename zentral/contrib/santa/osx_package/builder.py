import os
from django import forms
from django.utils.translation import ugettext_lazy as _
from zentral.utils.osx_package import EnrollmentForm, PackageBuilder
from zentral.contrib.santa.releases import Releases

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class SantaEnrollmentForm(EnrollmentForm):
    MONITOR_MODE = 1
    LOCKDOWN_MODE = 2
    release = forms.ChoiceField(
        label=_("Release"),
        choices=[],
        initial="",
        help_text="Choose a santa release to be installed with the enrollment package.",
        required=False
    )
    mode = forms.ChoiceField(
        label=_("Mode"),
        choices=((MONITOR_MODE, _("Monitor")),
                 (LOCKDOWN_MODE, _("Lockdown"))),
        initial=MONITOR_MODE,
        help_text="In Monitor mode, only blacklisted binaries will be blocked. "
                  "In Lockdown mode, only whitelisted binaries will be allowed to run.")
    whitelist_regex = forms.CharField(
        label=_("Whitelist regex"),
        help_text="Matching binaries will be allowed to run, in both modes."
                  "Events will be logged with the 'ALLOW_SCOPE' decision.",
        required=False
    )
    blacklist_regex = forms.CharField(
        label=_("Blacklist regex"),
        help_text="In Monitor mode, executables whose paths are matched by this regex will be blocked.",
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
                choices.append(("", "Do not include santa"))
            # TODO: Async or cached to not slow down the web page
            r = Releases()
            for filename, version, created_at, download_url, is_local in r.get_versions():
                choices.append((filename, filename))
            release_field.choices = choices

    def get_build_kwargs(self):
        kwargs = super().get_build_kwargs()
        kwargs["mode"] = mode = int(self.cleaned_data.get("mode", self.MONITOR_MODE))
        if not self.update_for:
            kwargs["release"] = self.cleaned_data["release"]
        whitelist_regex = self.cleaned_data.get("whitelist_regex")
        if whitelist_regex:
            kwargs["whitelist_regex"] = whitelist_regex
        if mode == self.MONITOR_MODE:
            blacklist_regex = self.cleaned_data.get("blacklist_regex")
            if blacklist_regex:
                kwargs["blacklist_regex"] = blacklist_regex
        return kwargs

    def clean(self):
        cleaned_data = super().clean()
        mode = cleaned_data.get("mode")
        if mode:
            mode = int(mode)
            blacklist_regex = cleaned_data.get("blacklist_regex")
            if mode == self.LOCKDOWN_MODE and blacklist_regex:
                self.add_error("blacklist_regex",
                               "Can't use a blacklist regex in Lockdown mode.")


class SantaZentralEnrollPkgBuilder(PackageBuilder):
    standalone = True
    name = "Zentral Santa Enrollment"
    form = SantaEnrollmentForm
    zentral_module = "zentral.contrib.santa"
    package_name = "zentral_santa_enroll.pkg"
    base_package_identifier = "io.zentral.santa_enroll"
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

    def extra_build_steps(self, mode=None, blacklist_regex=None, whitelist_regex=None, **kwargs):
        if mode is None:
            mode = self.form.MONITOR_MODE
        elif mode not in {self.form.MONITOR_MODE, self.form.LOCKDOWN_MODE}:
            raise ValueError("Unknown monitor mode {}".format(mode))
        config_plist = self.get_root_path("var/db/santa/config.plist")
        self.replace_in_file(config_plist,
                             (("%TLS_HOSTNAME%", self.get_tls_hostname()),
                              ("%MODE%", str(mode))))
        postinstall_script = self.get_build_path("scripts", "postinstall")
        self.replace_in_file(postinstall_script,
                             (("%API_SECRET%", self.make_api_secret()),
                              ("%TLS_HOSTNAME%", self.get_tls_hostname())))
        tls_server_certs_install_path = self.include_tls_server_certs()
        self.set_plist_keys(config_plist,
                            [("ServerAuthRootsFile", tls_server_certs_install_path)])
        if blacklist_regex:
            self.set_plist_keys(config_plist, [("BlacklistRegex", blacklist_regex)])
        if whitelist_regex:
            self.set_plist_keys(config_plist, [("WhitelistRegex", whitelist_regex)])
