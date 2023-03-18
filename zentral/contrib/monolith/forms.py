from django import forms
from django.db.models import Q
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from .attachments import PackageFile
from .exceptions import AttachmentError
from .models import (Catalog, Enrollment,
                     Manifest, ManifestCatalog, ManifestSubManifest,
                     PkgInfo, PkgInfoName, SubManifest, SubManifestPkgInfo)


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
        fields = ('meta_business_unit', 'name')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["meta_business_unit"].widget = forms.HiddenInput()
        self.fields['meta_business_unit'].queryset = MetaBusinessUnit.objects.available_for_api_enrollment()


class ManifestSearchForm(forms.Form):
    name = forms.CharField(label="Name", required=False,
                           widget=forms.TextInput(attrs={"autofocus": "true",
                                                         "size": 32,
                                                         "placeholder": "Name or business unit name"}))

    def get_queryset(self):
        qs = Manifest.objects.select_related("meta_business_unit").all()
        name = self.cleaned_data.get("name")
        if name:
            qs = qs.filter(Q(name__icontains=name) | Q(meta_business_unit__name__icontains=name))
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
                                      | Q(submanifestpkginfo__pkg_info_name__name__icontains=keywords))
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


class SubManifestItemFormMixin:
    def clean(self):
        super().clean()
        featured_item = self.cleaned_data.get("featured_item")
        key = self.cleaned_data.get("key")
        if featured_item and key not in ("default_installs", "optional_installs"):
            self.add_error("featured_item", "Only optional install items can be featured")


class SubManifestPkgInfoForm(SubManifestItemFormMixin, forms.ModelForm):
    excluded_tags = forms.ModelMultipleChoiceField(queryset=Tag.objects.all(), required=False,
                                                   widget=forms.SelectMultiple(attrs={"class": "hide-if-not-install"}))
    default_shard = forms.IntegerField(min_value=0, max_value=1000, required=False, initial=100,
                                       widget=forms.TextInput(attrs={"class": "hide-if-not-install"}))
    shard_modulo = forms.IntegerField(min_value=1, max_value=1000, required=False, initial=100,
                                      widget=forms.TextInput(attrs={"class": "hide-if-not-install"}))

    def __init__(self, *args, **kwargs):
        self.sub_manifest = kwargs.pop('sub_manifest', None)
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.sub_manifest = self.instance.sub_manifest

        # pin qs
        pin_qs = PkgInfoName.objects.distinct().filter(pkginfo__id__isnull=False,
                                                       pkginfo__archived_at__isnull=True,
                                                       pkginfo__update_for=None)
        if not self.instance.pk:
            pin_qs = pin_qs.exclude(submanifestpkginfo__sub_manifest=self.sub_manifest)
        self.fields['pkg_info_name'].queryset = pin_qs

        if self.instance.pk:
            self.fields["excluded_tags"].initial = [tag.pk for tag in self.instance.excluded_tags]
            self.fields["default_shard"].initial = self.instance.default_shard
            self.fields["shard_modulo"].initial = self.instance.shard_modulo
            self.fields["pkg_info_name"].widget = forms.HiddenInput()

        # tag qs
        tag_qs = Tag.objects.select_related("meta_business_unit", "taxonomy").all()
        if self.sub_manifest.meta_business_unit:
            tag_qs = tag_qs.filter(
                Q(meta_business_unit__isnull=True) | Q(meta_business_unit=self.sub_manifest.meta_business_unit)
            )
        self.fields['excluded_tags'].queryset = tag_qs

        # tags shards
        self.tag_shards = []
        existing_tag_shard_dict = {}
        if self.instance.pk:
            existing_tag_shard_dict = {ts["tag"]: ts["shard"] for ts in self.instance.tag_shards}
        for tag in tag_qs:
            self.tag_shards.append(
                (tag, tag in existing_tag_shard_dict, existing_tag_shard_dict.get(tag, self.instance.shard_modulo))
            )
        self.tag_shards.sort(key=lambda t: t[0].name.lower())

    def clean(self):
        super().clean()
        # shards
        default_shard = self.cleaned_data.get("default_shard")
        shard_modulo = self.cleaned_data.get("shard_modulo")
        if default_shard and shard_modulo and shard_modulo < default_shard:
            self.add_error("default_shard", "Must be less than or equal to the shard modulo")
        # options
        options = {}
        if self.cleaned_data.get("key") in ("managed_installs", "optional_installs"):
            excluded_tags = self.cleaned_data.get("excluded_tags")
            if excluded_tags:
                options["excluded_tags"] = [tag.name for tag in excluded_tags]
            if default_shard is not None:
                options.setdefault("shards", {})["default"] = default_shard
            if shard_modulo is not None:
                options.setdefault("shards", {})["modulo"] = shard_modulo
            tag_shards = {}
            for tag, _, _ in self.tag_shards:
                try:
                    shard = int(self.data[f"tag-shard-{tag.pk}"])
                except Exception:
                    continue
                if isinstance(shard_modulo, int):
                    shard = min(shard, shard_modulo)
                tag_shards[tag.name] = shard
            if tag_shards:
                options.setdefault("shards", {})["tags"] = tag_shards
        self.instance.options = options

    class Meta:
        model = SubManifestPkgInfo
        fields = ('pkg_info_name', 'key', 'condition', 'featured_item')


class PackageForm(forms.ModelForm):
    file = forms.FileField(required=True)
    display_name = forms.CharField(required=False)
    description = forms.CharField(widget=forms.Textarea(attrs={"rows": 10}), required=False)
    excluded_tags = forms.ModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)
    shard_modulo = forms.IntegerField(min_value=1, max_value=1000, required=False, initial=100)
    default_shard = forms.IntegerField(min_value=0, max_value=1000, required=False, initial=100)
    field_order = [
        "file",
        "name",
        "display_name", "description", "category",
        "requires", "update_for",
        "catalogs",
        "excluded_tags",
        "shard_modulo",
        "default_shard",
    ]

    def __init__(self, *args, **kwargs):
        self.pkg_info_name = kwargs.pop("pkg_info_name", None)
        super().__init__(*args, **kwargs)
        # do not show names with pkg infos from the repository
        self.fields["name"].queryset = self.fields["name"].queryset.exclude(pkginfo__file="")
        data = self.instance.data
        if data:
            # re-hydrate some form fields with the pkg info data
            display_name = data.get("display_name")
            if display_name:
                self.fields["display_name"].initial = display_name
            description = data.get("description")
            if description:
                self.fields["description"].initial = description
            # remove the file field
            del self.fields["file"]
            # remove the name field
            del self.fields["name"]
            # prepare the shards fields
            self.fields["excluded_tags"].initial = [tag.pk for tag in self.instance.excluded_tags]
            self.fields["default_shard"].initial = self.instance.default_shard
            self.fields["shard_modulo"].initial = self.instance.shard_modulo
        # hide name field if necessary
        if self.pkg_info_name:
            del self.fields["name"]
        # tags
        tag_qs = Tag.objects.select_related("meta_business_unit", "taxonomy").all()
        self.fields['excluded_tags'].queryset = tag_qs
        # tags shards
        self.tag_shards = []
        existing_tag_shard_dict = {}
        if self.instance.pk:
            existing_tag_shard_dict = {ts["tag"]: ts["shard"] for ts in self.instance.tag_shards}
        for tag in tag_qs:
            self.tag_shards.append(
                (tag, tag in existing_tag_shard_dict, existing_tag_shard_dict.get(tag, self.instance.shard_modulo))
            )
        self.tag_shards.sort(key=lambda t: t[0].name.lower())

    class Meta:
        model = PkgInfo
        fields = ("file",
                  "name", "catalogs",
                  "category",
                  "requires", "update_for",
                  "file")

    def clean_file(self):
        uploaded_file = self.cleaned_data["file"]
        try:
            self.cleaned_data["package_file"] = PackageFile(uploaded_file)
        except AttachmentError as e:
            raise forms.ValidationError(e.message)
        return None

    def clean(self):
        self.instance.local = True
        if self.instance.data is None:
            self.instance.data = {}
        data = self.instance.data
        # shards
        default_shard = self.cleaned_data.get("default_shard")
        shard_modulo = self.cleaned_data.get("shard_modulo")
        if default_shard and shard_modulo and shard_modulo < default_shard:
            self.add_error("default_shard", "Must be less than or equal to the shard modulo")
        # zentral options
        zentral_options = {}
        excluded_tags = self.cleaned_data.get("excluded_tags")
        if excluded_tags:
            zentral_options["excluded_tags"] = [tag.name for tag in excluded_tags]
        if default_shard is not None:
            zentral_options.setdefault("shards", {})["default"] = default_shard
        if shard_modulo is not None:
            zentral_options.setdefault("shards", {})["modulo"] = shard_modulo
        tag_shards = {}
        for tag, _, _ in self.tag_shards:
            try:
                shard = int(self.data[f"tag-shard-{tag.pk}"])
            except Exception:
                continue
            if isinstance(shard_modulo, int):
                shard = min(shard, shard_modulo)
            tag_shards[tag.name] = shard
        if tag_shards:
            zentral_options.setdefault("shards", {})["tags"] = tag_shards
        if zentral_options:
            data["zentral_monolith"] = zentral_options
        pin = self.cleaned_data.get("name", self.pkg_info_name)
        if pin:
            data["name"] = pin.name
        display_name = self.cleaned_data["display_name"]
        if display_name:
            data["display_name"] = display_name
        elif "display_name" in data:
            del data["display_name"]
        description = self.cleaned_data["description"]
        if description:
            data["description"] = description
        elif "description" in data:
            del data["description"]
        category = self.cleaned_data["category"]
        if category:
            data["category"] = category.name
        elif "category" in data:
            del data["category"]
        requires = self.cleaned_data["requires"]
        if requires:
            data["requires"] = [pin.name for pin in requires]
        elif "requires" in data:
            del data["requires"]
        update_for = self.cleaned_data["update_for"]
        if update_for:
            data["update_for"] = [pin.name for pin in update_for]
        elif "update_for" in data:
            del data["update_for"]
        pf = self.cleaned_data.get("package_file")
        if pf:
            data.update(pf.get_pkginfo_data())
            uf = pf.uploaded_file
            if uf.name:
                data["installer_item_location"] = uf.name
            self.instance.version = data.get("version")
        if self.pkg_info_name:
            self.instance.name = self.pkg_info_name

    def save(self, *args, **kwargs):
        pi = super().save()
        pf = self.cleaned_data.get("package_file")
        if pf:
            pi.file = pf.uploaded_file
            pi.save()
        for manifest in pi.name.manifests():
            manifest.bump_version()
        return pi


class ScriptForm(forms.Form):
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
        field.queryset = field.queryset.exclude(id__in=[mc.catalog_id
                                                        for mc in self.manifest.manifestcatalog_set.all()])
        field = self.fields['tags']
        field.queryset = Tag.objects.available_for_meta_business_unit(self.manifest.meta_business_unit)

    def save(self):
        mc = ManifestCatalog(manifest=self.manifest,
                             catalog=self.cleaned_data['catalog'])
        mc.save()
        mc.tags.set(self.cleaned_data['tags'])
        return mc


class EditManifestCatalogForm(forms.Form):
    tags = forms.ModelMultipleChoiceField(queryset=Tag.objects.none(), required=False)

    def __init__(self, *args, **kwargs):
        self.manifest = kwargs.pop('manifest')
        self.mc = ManifestCatalog.objects.get(manifest=self.manifest, catalog=kwargs.pop("catalog"))
        super().__init__(*args, **kwargs)
        field = self.fields['tags']
        field.queryset = Tag.objects.available_for_meta_business_unit(self.manifest.meta_business_unit)
        field.initial = self.mc.tags.all()

    def save(self):
        self.mc.tags.set(self.cleaned_data['tags'])
        return self.mc


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
        ManifestCatalog.objects.filter(manifest=self.manifest,
                                       catalog=self.cleaned_data['catalog']).delete()


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


class EditManifestSubManifestForm(forms.Form):
    tags = forms.ModelMultipleChoiceField(queryset=Tag.objects.none(), required=False)

    def __init__(self, *args, **kwargs):
        self.manifest = kwargs.pop('manifest')
        self.msm = ManifestSubManifest.objects.get(manifest=self.manifest, sub_manifest=kwargs.pop("sub_manifest"))
        super().__init__(*args, **kwargs)
        field = self.fields['tags']
        field.queryset = Tag.objects.available_for_meta_business_unit(self.manifest.meta_business_unit)
        field.initial = self.msm.tags.all()

    def save(self):
        self.msm.tags.set(self.cleaned_data['tags'])
        return self.msm


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


class EnrollmentForm(forms.ModelForm):
    class Meta:
        model = Enrollment
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        self.meta_business_unit = kwargs.pop("meta_business_unit", None)
        self.manifest = kwargs.pop("manifest", None)
        assert self.manifest is None or self.meta_business_unit is None
        self.standalone = kwargs.pop("standalone", False)
        super().__init__(*args, **kwargs)
        # hide manifest dropdown if manifest is fixed
        # the value will be set in the clean_manifest method
        # TODO: kind of a hack
        if self.manifest:
            self.fields["manifest"].widget = forms.HiddenInput()
            self.fields["manifest"].required = False

    def clean_manifest(self):
        if self.manifest:
            return self.manifest
        else:
            return self.cleaned_data.get("manifest")

    def clean(self):
        cleaned_data = super().clean()
        if self.meta_business_unit:
            manifest = cleaned_data.get("manifest")
            if manifest and manifest.meta_business_unit != self.meta_business_unit:
                raise forms.ValidationError("Manifest business unit != meta business unit")
        return cleaned_data
