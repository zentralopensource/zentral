from django import forms
from django.db import IntegrityError, transaction
from django.db.models import F, Max, Q
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from .attachments import MobileconfigFile, PackageFile
from .exceptions import AttachmentError
from .models import (Catalog, Manifest, ManifestCatalog, ManifestSubManifest,
                     PkgInfo, PkgInfoName, SubManifest,
                     SubManifestPkgInfo, SubManifestAttachment)


class PkgInfoSearchForm(forms.Form):
    name = forms.CharField(label="Name", required=False,
                           widget=forms.TextInput(attrs={"placeholder": "name"}))
    catalog = forms.ModelChoiceField(queryset=Catalog.objects.filter(archived_at__isnull=True),
                                     required=False)

    def is_initial(self):
        return not {k: v for k, v in self.cleaned_data.items() if v}


class UpdatePkgInfoCatalogForm(forms.ModelForm):
    """Force the selection of only one catalog to conform to our use of munki

    This is sadly hacky in order to make the m2m relation behave like a fk in the form
    """
    catalogs = forms.ModelChoiceField(queryset=Catalog.objects.all(), required=True, empty_label=None)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.initial = {"catalogs": self.instance.catalogs.all()[0]}

    def clean_catalogs(self):
        catalogs = self.cleaned_data["catalogs"]
        if catalogs:
            return [catalogs]

    class Meta:
        fields = ("catalogs",)
        model = PkgInfo


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
        fields = ('key', 'pkg_info_name')


class SubManifestAttachmentForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        self.sub_manifest = kwargs.pop('sub_manifest')
        super().__init__(*args, **kwargs)

    class Meta:
        model = SubManifestAttachment
        fields = ('key', 'file',)

    def clean_file(self):
        f = self.cleaned_data["file"]
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
                pass
            else:
                break
        else:
            raise Exception("Could not find valid version #")
        return sma


class SubManifestScriptForm(forms.Form):
    name = forms.CharField(max_length=256, required=True)
    key = forms.ChoiceField(choices=(("managed_installs", "Managed Installs"),
                                     ("managed_uninstalls", "Managed Uninstalls")),
                            required=True)
    description = forms.CharField(required=True, widget=forms.Textarea())
    installcheck_script = forms.CharField(
        label="install check script",
        help_text="If present, this script is executed to determine if an item needs to be installed. "
                  "A return code of 0 means install is needed.",
        required=False,
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
            'postinstall_script': self.cleaned_data["postinstall_script"],
        }
        installcheck_script = self.cleaned_data["installcheck_script"]
        if installcheck_script:
            pkg_info["installcheck_script"] = installcheck_script
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
        mc.tags = self.cleaned_data['tags']
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


class AddManifestSubManifestForm(forms.Form):
    sub_manifest = forms.ModelChoiceField(queryset=SubManifest.objects.all())
    tags = forms.ModelMultipleChoiceField(queryset=Tag.objects.none(), required=False)

    def __init__(self, *args, **kwargs):
        self.manifest = kwargs.pop('manifest')
        super().__init__(*args, **kwargs)
        field = self.fields['sub_manifest']
        field.queryset = field.queryset.exclude(id__in=[sm.id for sm in self.manifest.sub_manifests()])
        field = self.fields['tags']
        field.queryset = Tag.objects.available_for_meta_business_unit(self.manifest.meta_business_unit)

    def save(self):
        msn = ManifestSubManifest(manifest=self.manifest,
                                  sub_manifest=self.cleaned_data['sub_manifest'])
        msn.save()
        msn.tags = self.cleaned_data['tags']
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
