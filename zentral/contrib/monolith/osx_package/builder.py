import os
from django import forms
from django.utils.translation import ugettext_lazy as _
from zentral.utils.osx_package import EnrollmentForm, PackageBuilder
from zentral.contrib.monolith.releases import DEPNotifyReleases, MunkiReleases

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class MonolithEnrollmentForm(EnrollmentForm):
    release = forms.ChoiceField(
        label=_("Release"),
        choices=[],
        initial="",
        help_text="Choose a munki release to be installed with the enrollment package.",
        required=False
    )
    no_restart = forms.BooleanField(
        label=_("No restart"),
        initial=False,
        help_text="Remove the launchd package restart requirement.",
        required=False,
    )
    depnotify_release = forms.ChoiceField(
        label=_("Include DEPNotify?"),
        choices=[],
        initial="",
        help_text="Choose a DEPNotify release to be installed.",
        required=False
    )
    depnotify_commands = forms.CharField(
        label=_("DEPNotify startup commands"),
        help_text="Configure DEPNotify with some commands.",
        widget=forms.Textarea(attrs={'rows': 5}),
        required=False
    )
    eula = forms.CharField(
        label=_("EULA"),
        help_text="This text will be displayed in DEPNotify, and the user will be asked to accept it.",
        widget=forms.Textarea(attrs={'rows': 10}),
        required=False
    )
    setup_script = forms.CharField(
        label=_("Setup script"),
        help_text="A script that will be run when this enrollment package is installed.",
        widget=forms.Textarea(attrs={'rows': 10}),
        required = False
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        choices = []
        if not self.standalone:
            choices.append(("", "Do not include munki"))
        # TODO: Async or cached to not slow down the web page
        munki_releases = MunkiReleases()
        for filename, version, created_at, download_url, is_local in munki_releases.get_versions():
            choices.append((filename, filename))
        self.fields["release"].choices = choices
        choices = [("", "---")]
        depnotify_releases = DEPNotifyReleases()
        for filename, version, created_at, download_url, is_local in depnotify_releases.get_versions():
            choices.append((filename, filename))
        self.fields["depnotify_release"].choices = choices

    def clean(self):
        super().clean()
        if self.cleaned_data.get("depnotify_commands") and not self.cleaned_data.get("depnotify_release"):
            self.add_error("depnotify_release",
                           "You need to pick a DEPNotify release to use the commands.")
        if self.cleaned_data.get("eula") and not self.cleaned_data.get("depnotify_release"):
            self.add_error("depnotify_release",
                           "You need to pick a DEPNotify release to display the EULA.")

    def clean_depnotify_commands(self):
        depnotify_commands = self.cleaned_data.get("depnotify_commands")
        if depnotify_commands:
            depnotify_commands = depnotify_commands.strip().replace("\r\n", "\n")
        return depnotify_commands

    def clean_setup_script(self):
        setup_script = self.cleaned_data.get("setup_script")
        if setup_script:
            setup_script = setup_script.strip().replace("\r\n", "\n")
        return setup_script

    def clean_eula(self):
        eula = self.cleaned_data.get("eula")
        if eula:
            eula = eula.strip().replace("\r\n", "\n")
        return eula

    def get_build_kwargs(self):
        kwargs = super().get_build_kwargs()
        kwargs["release"] = self.cleaned_data["release"]
        kwargs["no_restart"] = self.cleaned_data.get("no_restart", False)
        kwargs["depnotify_release"] = self.cleaned_data["depnotify_release"]
        kwargs["depnotify_commands"] = self.cleaned_data["depnotify_commands"]
        kwargs["eula"] = self.cleaned_data["eula"]
        kwargs["setup_script"] = self.cleaned_data["setup_script"]
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
            munki_releases = MunkiReleases()
            return munki_releases.get_requested_package(release)

    def get_extra_packages(self):
        depnotify_release = self.build_kwargs.get("depnotify_release")
        if depnotify_release:
            depnotify_releases = DEPNotifyReleases()
            yield depnotify_releases.get_requested_package(depnotify_release)

    def get_product_archive_title(self):
        if self.build_kwargs.get("release"):
            return self.build_kwargs.get("product_archive_title", self.name)

    def extra_build_steps(self, **kwargs):
        postinstall_script = self.get_build_path("scripts", "postinstall")

        # setup script
        setup_script_path = ""
        setup_script = self.build_kwargs.get("setup_script")
        if setup_script:
            setup_script_path = "/usr/local/zentral/monolith/setup_script"
            self.create_file_with_content_string(setup_script_path[1:], setup_script, executable=True)

        # software_repo_url
        # TODO: hardcoded
        software_repo_url = "https://{}/monolith/munki_repo".format(self.get_tls_hostname())

        # depnotify
        depnotify_release = self.build_kwargs.get("depnotify_release")
        if depnotify_release:
            include_depnotify = 1
        else:
            include_depnotify = 0

        # EULA
        eula = self.build_kwargs.get("eula")
        if eula:
            self.create_file_with_content_string("Users/Shared/eula.txt", eula)

        self.replace_in_file(postinstall_script,
                             (("%SETUP_SCRIPT_PATH%", setup_script_path),
                              ("%SOFTWARE_REPO_URL%", software_repo_url),
                              ("%API_SECRET%", self.make_api_secret()),
                              ("%TLS_CA_CERT%", self.include_tls_ca_cert()),
                              ("%INCLUDE_DEPNOTIFY%", str(include_depnotify)),
                              ("%DEPNOTIFY_COMMANDS%", self.build_kwargs.get("depnotify_commands") or "")))
        setup_script = self.build_kwargs.get("setup_script")

    def extra_product_archive_build_steps(self, pa_builder):
        no_restart = self.build_kwargs.get("no_restart")
        if no_restart:
            pa_builder.remove_pkg_ref_on_conclusion("com.googlecode.munki.launchd")
