import json
from django import forms
from django.db import IntegrityError, transaction
from django.db.models import F, Max, Q
from django.urls import reverse
from zentral.conf import settings
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from zentral.utils.api_views import make_secret
from .attachments import MobileconfigFile, PackageFile
from .exceptions import AttachmentError
from .models import (CacheServer, Catalog, Enrollment,
                     Manifest, ManifestCatalog, ManifestSubManifest,
                     Printer, PrinterPPD,
                     PkgInfoName, SubManifest,
                     SubManifestPkgInfo, SubManifestAttachment)
from .ppd import get_ppd_information


class PkgInfoSearchForm(forms.Form):
    name = forms.CharField(label="Name", required=False,
                           widget=forms.TextInput(attrs={"placeholder": "name"}))
    catalog = forms.ModelChoiceField(queryset=Catalog.objects.filter(archived_at__isnull=True),
                                     required=False)

    def is_initial(self):
        return not {k: v for k, v in self.cleaned_data.items() if v}


class ManifestForm(forms.ModelForm):
    class Meta:
        model = Manifest
        fields = ('meta_business_unit',)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        mbu_qs = MetaBusinessUnit.objects.available_for_api_enrollment()
        if self.instance.pk:
            mbu_qs = mbu_qs.filter(Q(manifest=None) | Q(pk=self.instance.meta_business_unit.id))
        else:
            mbu_qs = mbu_qs.filter(manifest=None)
        self.fields['meta_business_unit'].queryset = mbu_qs


class ManifestSearchForm(forms.Form):
    meta_business_unit_name = forms.CharField(label="Business unit name", required=False,
                                              widget=forms.TextInput(attrs={"placeholder": "Business unit name…"}))

    def get_queryset(self):
        qs = Manifest.objects.select_related("meta_business_unit").all()
        meta_business_unit_name = self.cleaned_data.get("meta_business_unit_name")
        if meta_business_unit_name:
            qs = qs.filter(meta_business_unit__name__icontains=meta_business_unit_name)
        return qs


class SubManifestSearchForm(forms.Form):
    keywords = forms.CharField(label="Keywords", required=False,
                               widget=forms.TextInput(attrs={"placeholder": "Keywords…"}))

    def get_queryset(self):
        qs = SubManifest.objects.select_related("meta_business_unit").all()
        keywords = self.cleaned_data.get("keywords")
        if keywords:
            qs = qs.distinct().filter(Q(name__icontains=keywords)
                                      | Q(description__icontains=keywords)
                                      | Q(meta_business_unit__name__icontains=keywords)
                                      | Q(submanifestpkginfo__pkg_info_name__name__icontains=keywords)
                                      | Q(submanifestattachment__name__icontains=keywords))
        return qs


class SubManifestForm(forms.ModelForm):
    class Meta:
        model = SubManifest
        fields = ('meta_business_unit', 'name', 'description')

    def clean_meta_business_unit(self):
        mbu = self.cleaned_data.get("meta_business_unit")
        if mbu and self.instance.pk:
            linked_mbu = {manifest.meta_business_unit
                          for _, manifest in self.instance.manifests_with_tags()}
            if linked_mbu - {mbu}:
                raise forms.ValidationError(
                    "Cannot restrict this sub manifest to this business unit. "
                    "It is already included in some other business units."
                )
        return mbu

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['meta_business_unit'].queryset = MetaBusinessUnit.objects.available_for_api_enrollment()


class SubManifestPkgInfoForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        self.sub_manifest = kwargs.pop('sub_manifest')
        super().__init__(*args, **kwargs)
        pin_qs = PkgInfoName.objects.distinct().filter(pkginfo__id__isnull=False,
                                                       pkginfo__archived_at__isnull=True,
                                                       pkginfo__update_for=None).exclude(
            submanifestpkginfo__sub_manifest=self.sub_manifest)
        self.fields['pkg_info_name'].queryset = pin_qs

    class Meta:
        model = SubManifestPkgInfo
        fields = ('key', 'condition', 'featured_item', 'pkg_info_name')


class SubManifestAttachmentForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        self.sub_manifest = kwargs.pop('sub_manifest')
        super().__init__(*args, **kwargs)

    class Meta:
        model = SubManifestAttachment
        fields = ('key', 'condition', 'featured_item', 'file',)

    def clean_file(self):
        f = self.cleaned_data["file"]
        if not f:
            raise forms.ValidationError("You need to select a file.")
        error_messages = []
        for file_class in (MobileconfigFile, PackageFile):
            try:
                af = file_class(f)
            except AttachmentError as e:
                error_messages.append(e.message)
            else:
                break
        else:
            raise forms.ValidationError(", ".join(error_messages))
        self.attachment_file = af
        return f

    def save(self, *args, **kwargs):
        sma = super().save(commit=False)
        sma.sub_manifest = self.sub_manifest
        sma.type = self.attachment_file.type
        sma.name = self.attachment_file.name
        sma.identifier = self.attachment_file.identifier
        for i in range(10):  # 10 trials max
            max_version = SubManifestAttachment.objects.filter(
                sub_manifest=self.sub_manifest,
                name=sma.name
            ).aggregate(Max("version"))["version__max"]
            sma.version = (max_version or 0) + 1
            sma.pkg_info = self.attachment_file.make_package_info(sma)
            try:
                with transaction.atomic():
                    sma.save()
            except IntegrityError:
                raise
            else:
                break
        else:
            raise Exception("Could not find valid version #")
        # trash other versions
        for sma_with_different_version in (SubManifestAttachment.objects.filter(
                                               sub_manifest=self.sub_manifest,
                                               name=sma.name
                                           ).exclude(version=sma.version)):
            sma_with_different_version.mark_as_trashed()
        return sma


class SubManifestScriptForm(forms.Form):
    DEFAULT_INSTALL_CHECK_SCRIPT = (
        "#!/bin/bash\n\n"
        "# WARNING: executed at every Munki run!\n\n"
        "exit 0"
    )
    name = forms.CharField(max_length=256, required=True)
    key = forms.ChoiceField(choices=(("managed_installs", "Managed Installs"),
                                     ("managed_uninstalls", "Managed Uninstalls")),
                            required=True)
    description = forms.CharField(required=True, widget=forms.Textarea())
    installcheck_script = forms.CharField(
        label="install check script",
        help_text="This script is executed to determine if an item needs to be installed. "
                  "A return code of 0 means install is needed.",
        required=True,
        initial=DEFAULT_INSTALL_CHECK_SCRIPT,
        widget=forms.Textarea(),
    )
    postinstall_script = forms.CharField(
        label="post install script",
        help_text="The main script.",
        required=True,
        widget=forms.Textarea(),
    )
    uninstall_script = forms.CharField(
        label="uninstall script",
        help_text="Script that performs an uninstall.",
        required=False,
        widget=forms.Textarea(),
    )

    def __init__(self, *args, **kwargs):
        self.sub_manifest = kwargs.pop('sub_manifest')
        self.script = kwargs.pop('script', None)
        super().__init__(*args, **kwargs)

    def clean(self):
        super().clean()
        key = self.cleaned_data["key"]
        if key == "managed_uninstalls" and not self.cleaned_data["uninstall_script"]:
            self.add_error("uninstall_script", "Can't be empty if managed uninstalls")
        return self.cleaned_data

    def save(self, *args, **kwargs):
        name = self.cleaned_data["name"]
        key = self.cleaned_data["key"]
        pkg_info = {
            'display_name': name,
            'description': self.cleaned_data["description"],
            'autoremove': False,
            'unattended_install': True,
            'installer_type': 'nopkg',
            'uninstallable': True,
            'unattended_uninstall': True,
            'minimum_munki_version': '2.2',
            'minimum_os_version': '10.6.0',  # TODO: HARDCODED !!!
            'installcheck_script': self.cleaned_data["installcheck_script"],
            'postinstall_script': self.cleaned_data["postinstall_script"],
        }
        uninstall_script = self.cleaned_data["uninstall_script"]
        if uninstall_script:
            pkg_info["uninstall_method"] = "uninstall_script"
            pkg_info["uninstall_script"] = uninstall_script
        if not self.script:
            self.script = SubManifestAttachment(
                sub_manifest=self.sub_manifest,
                type="script",
                key=key,
                name=name,
                pkg_info=pkg_info,
                version=1,
            )
            self.script.save()
        else:
            self.script.name = name
            self.script.key = key
            self.script.version = F("version") + 1
            self.script.pkg_info = pkg_info
            self.script.save()
            self.script.refresh_from_db()
        self.script.pkg_info["version"] = "{}.0".format(self.script.version)
        self.script.save()
        return self.script


class AddManifestCatalogForm(forms.Form):
    catalog = forms.ModelChoiceField(queryset=Catalog.objects.filter(archived_at__isnull=True))
    tags = forms.ModelMultipleChoiceField(queryset=Tag.objects.none(), required=False)

    def __init__(self, *args, **kwargs):
        self.manifest = kwargs.pop('manifest')
        super().__init__(*args, **kwargs)
        field = self.fields['catalog']
        field.queryset = field.queryset.exclude(id__in=[c.id for c in self.manifest.catalogs()])
        field = self.fields['tags']
        field.queryset = Tag.objects.available_for_meta_business_unit(self.manifest.meta_business_unit)

    def save(self):
        mc = ManifestCatalog(manifest=self.manifest,
                             catalog=self.cleaned_data['catalog'])
        mc.save()
        mc.tags.set(self.cleaned_data['tags'])
        self.manifest.save()  # updated_at
        return mc


class DeleteManifestCatalogForm(forms.Form):
    catalog = forms.ModelChoiceField(queryset=Catalog.objects.all(),
                                     widget=forms.HiddenInput)

    def __init__(self, *args, **kwargs):
        self.manifest = kwargs.pop('manifest')
        super().__init__(*args, **kwargs)
        field = self.fields['catalog']
        field.queryset = field.queryset.filter(id__in=[mc.catalog_id
                                                       for mc in self.manifest.manifestcatalog_set.all()])

    def save(self):
        number_deleted, _ = ManifestCatalog.objects.filter(manifest=self.manifest,
                                                           catalog=self.cleaned_data['catalog']).delete()
        if number_deleted:
            self.manifest.save()  # updated_at


class AddManifestEnrollmentPackageForm(forms.Form):
    tags = forms.ModelMultipleChoiceField(queryset=Tag.objects.none(), required=False)

    def __init__(self, *args, **kwargs):
        self.manifest = kwargs.pop('manifest')
        super().__init__(*args, **kwargs)
        field = self.fields['tags']
        field.queryset = Tag.objects.available_for_meta_business_unit(self.manifest.meta_business_unit)


class ManifestPrinterForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        self.manifest = kwargs.pop('manifest')
        super().__init__(*args, **kwargs)
        field = self.fields['tags']
        field.queryset = Tag.objects.available_for_meta_business_unit(self.manifest.meta_business_unit)

    class Meta:
        model = Printer
        fields = ["tags",
                  "name", "location",
                  "scheme", "address",
                  "shared", "error_policy", "ppd",
                  "required_package"]


class AddManifestSubManifestForm(forms.Form):
    sub_manifest = forms.ModelChoiceField(queryset=SubManifest.objects.all())
    tags = forms.ModelMultipleChoiceField(queryset=Tag.objects.none(), required=False)

    def __init__(self, *args, **kwargs):
        self.manifest = kwargs.pop('manifest')
        super().__init__(*args, **kwargs)
        field = self.fields['sub_manifest']
        field.queryset = (field.queryset.filter(Q(meta_business_unit__isnull=True)
                                                | Q(meta_business_unit=self.manifest.meta_business_unit))
                                        .exclude(id__in=[sm.id for sm in self.manifest.sub_manifests()]))
        field = self.fields['tags']
        field.queryset = Tag.objects.available_for_meta_business_unit(self.manifest.meta_business_unit)

    def save(self):
        msn = ManifestSubManifest(manifest=self.manifest,
                                  sub_manifest=self.cleaned_data['sub_manifest'])
        msn.save()
        msn.tags.set(self.cleaned_data['tags'])
        self.manifest.save()  # updated_at
        return msn


class DeleteManifestSubManifestForm(forms.Form):
    sub_manifest = forms.ModelChoiceField(queryset=SubManifest.objects.all(),
                                          widget=forms.HiddenInput)

    def __init__(self, *args, **kwargs):
        self.manifest = kwargs.pop('manifest')
        super().__init__(*args, **kwargs)
        field = self.fields['sub_manifest']
        field.queryset = field.queryset.filter(id__in=[msm.sub_manifest_id
                                                       for msm in self.manifest.manifestsubmanifest_set.all()])

    def save(self):
        number_deleted, _ = ManifestSubManifest.objects.filter(manifest=self.manifest,
                                                               sub_manifest=self.cleaned_data['sub_manifest']).delete()
        if number_deleted:
            self.manifest.save()  # updated_at


class CacheServerBaseForm(forms.Form):
    name = forms.CharField(max_length=256)
    base_url = forms.URLField(label="base URL")


class CacheServersPostForm(CacheServerBaseForm):
    def save(self, manifest, public_ip_address):
        cd = self.cleaned_data
        cache_server, _ = CacheServer.objects.update_or_create(
            name=cd["name"],
            manifest=manifest,
            defaults={"public_ip_address": public_ip_address,
                      "base_url": cd["base_url"]}
        )
        return cache_server


class ConfigureCacheServerForm(CacheServerBaseForm):
    def build_curl_command(self, manifest):
        business_unit = manifest.meta_business_unit.api_enrollment_business_units()[0]
        api_secret = make_secret('zentral.contrib.monolith', business_unit)
        json_payload = json.dumps(self.cleaned_data)
        tls_hostname = settings["api"]["tls_hostname"]
        path = reverse("monolith:cache_servers")
        # TODO: what if there is a ' in the json payload ?
        return ("curl -XPOST "
                "-H 'Zentral-API-Secret: {api_secret}' "
                "-d '{json_payload}' "
                "{tls_hostname}{path}").format(api_secret=api_secret,
                                               json_payload=json_payload,
                                               tls_hostname=tls_hostname,
                                               path=path)


class UploadPPDForm(forms.ModelForm):
    class Meta:
        model = PrinterPPD
        fields = ['file']

    def clean_file(self):
        f = self.cleaned_data["file"]
        try:
            self.cleaned_data["ppd_info"] = get_ppd_information(f)
        except Exception:
            raise forms.ValidationError("Could not parse PPD file %s." % f.name)
        return f

    def save(self, *args, **kwargs):
        ppd = PrinterPPD.objects.create(**self.cleaned_data["ppd_info"])
        uploaded_file = self.cleaned_data["file"]
        ppd.file.save(uploaded_file.name, uploaded_file)
        return ppd


class EnrollmentForm(forms.ModelForm):
    class Meta:
        model = Enrollment
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        self.meta_business_unit = kwargs.pop("meta_business_unit", None)
        self.standalone = kwargs.pop("standalone", False)
        super().__init__(*args, **kwargs)
        # hide manifest dropdown if manifest/mbu is fixed
        # the value will be set in the clean_manifest method
        # TODO: kind of a hack
        if self.meta_business_unit:
            self.fields["manifest"].widget = forms.HiddenInput()
            self.fields["manifest"].required = False

    def clean_manifest(self):
        if self.meta_business_unit:
            return self.meta_business_unit.manifest
        else:
            return self.cleaned_data.get("manifest")
