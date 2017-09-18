import os
import shutil
from django import forms
from django.utils.translation import ugettext_lazy as _
from zentral.utils.osx_package import EnrollmentForm, PackageBuilder
from zentral.utils.filebeat_releases import Releases

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class AuditShipperForm(EnrollmentForm):
    release = forms.ChoiceField(
        label=_("Release"),
        choices=[],
        initial="",
        help_text="Choose a filebeat release to be installed with the enrollment package.",
        required=True
    )
    client_certificate_path = forms.CharField(
        label=_("TLS client certificate path"),
        help_text="The local path to the client certificate for filebeat.",
        required=True
    )
    client_certificate_key_path = forms.CharField(
        label=_("TLS client certificate key path"),
        help_text="The local path to the client certificate key for filebeat.",
        required=True
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # TODO: Async or cached to not slow down the web page
        r = Releases()
        choices = []
        for filename, version, created_at, download_url, is_local in r.get_versions():
            choices.append((filename, filename))
        self.fields["release"].choices = choices

    def get_build_kwargs(self):
        kwargs = super().get_build_kwargs()
        for attr in ("release", "client_certificate_path", "client_certificate_key_path"):
            kwargs[attr] = self.cleaned_data[attr]
        return kwargs


class AuditZentralShipperPkgBuilder(PackageBuilder):
    standalone = True
    name = "Zentral Audit Shipper"
    form = AuditShipperForm
    zentral_module = "zentral.contrib.audit"
    package_name = "zentral_audit_shipper.pkg"
    base_package_identifier = "io.zentral.audit_shipper"
    build_tmpl_dir = os.path.join(BASE_DIR, "build.tmpl")

    def get_product_archive_title(self):
        return self.build_kwargs.get("product_archive_title")

    def extra_build_steps(self, release, client_certificate_path, client_certificate_key_path, **kwargs):
        r = Releases()
        local_path = r.get_requested_package(release)
        filebeat_path = self.get_root_path("usr/local/zentral/bin/filebeat")
        filebeat_dir = os.path.dirname(filebeat_path)
        if not os.path.exists(filebeat_dir):
            os.makedirs(filebeat_dir)
        shutil.copy(local_path, self.get_root_path("usr/local/zentral/bin/filebeat"))
        tls_server_certs_install_path = self.include_tls_server_certs()
        filebeat_config = self.get_root_path("usr/local/zentral/audit/filebeat.yml")
        self.replace_in_file(filebeat_config,
                             (("%TLS_HOSTNAME%", self.get_tls_hostname()),
                              ("%TLS_SERVER_CERTS%", tls_server_certs_install_path),
                              ("%TLS_CLIENT_CERT%", client_certificate_path),
                              ("%TLS_CLIENT_CERT_KEY%", client_certificate_key_path)))
        postinstall_script = self.get_build_path("scripts", "postinstall")
        self.replace_in_file(postinstall_script,
                             (("%TLS_HOSTNAME%", self.get_tls_hostname()),))
