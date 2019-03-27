from django import forms
from django.core.exceptions import ValidationError
from django.db import connection
from django.utils.text import slugify
from zentral.utils.forms import validate_sha256
from .models import (EnrollmentSecret,
                     MachineTag, MetaMachine,
                     MetaBusinessUnit, MetaBusinessUnitTag,
                     Source, Tag)


class MachineGroupSearchForm(forms.Form):
    name = forms.CharField(label="name", max_length=64, required=False)
    source = forms.ModelChoiceField(queryset=Source.objects.current_machine_group_sources(),
                                    required=False,
                                    widget=forms.Select(attrs={'class': 'form-control'}))


class MetaBusinessUnitSearchForm(forms.Form):
    name = forms.CharField(max_length=64, required=False)
    source = forms.ModelChoiceField(queryset=Source.objects.current_business_unit_sources(),
                                    required=False,
                                    widget=forms.Select(attrs={'class': 'form-control'}))
    tag = forms.ModelChoiceField(queryset=Tag.objects.distinct().filter(metabusinessunittag__isnull=False),
                                 required=False,
                                 widget=forms.Select(attrs={'class': 'form-control'}))


class MetaBusinessUnitForm(forms.ModelForm):
    class Meta:
        model = MetaBusinessUnit
        fields = ("name",)
        widgets = {"name": forms.TextInput}


class MergeMBUForm(forms.Form):
    mbu = forms.ModelMultipleChoiceField(queryset=MetaBusinessUnit.objects.all())
    dest_mbu = forms.ModelChoiceField(queryset=MetaBusinessUnit.objects.all())

    def merge(self):
        dest_mbu = self.cleaned_data['dest_mbu']
        tags = []
        for mbu in self.cleaned_data['mbu']:
            tags.extend(mbu.tags())
            if mbu == dest_mbu:
                continue
            for bu in mbu.businessunit_set.all():
                bu.set_meta_business_unit(dest_mbu)
            mbu.delete()
        for tag in set(tags).difference(dest_mbu.tags()):
            MetaBusinessUnitTag.objects.get_or_create(meta_business_unit=dest_mbu,
                                                      tag=tag)
        return dest_mbu


class MBUAPIEnrollmentForm(forms.ModelForm):
    class Meta:
        model = MetaBusinessUnit
        fields = []

    def enable_api_enrollment(self):
        if not self.instance.api_enrollment_business_units().count():
            self.instance.create_enrollment_business_unit()
        return self.instance


class CreateTagForm(forms.ModelForm):
    class Meta:
        model = Tag
        fields = ("meta_business_unit", "taxonomy", "name", "color")

    def clean(self):
        super().clean()
        taxonomy = self.cleaned_data["taxonomy"]
        meta_business_unit = self.cleaned_data["meta_business_unit"]
        if taxonomy and taxonomy.meta_business_unit and meta_business_unit \
           and taxonomy.meta_business_unit != meta_business_unit:
            self.add_error("meta_business_unit", "Should be either the taxonomy business unit or left empty")
        return self.cleaned_data


class UpdateTagForm(forms.ModelForm):
    class Meta:
        model = Tag
        fields = ("taxonomy", "name", "color")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.meta_business_unit:
            self.fields["taxonomy"].queryset = self.fields["taxonomy"].queryset.filter(
                meta_business_unit=self.instance.meta_business_unit
            )


class AddTagForm(forms.Form):
    existing_tag = forms.ModelChoiceField(label="existing tag", queryset=Tag.objects.none(), required=False)
    new_tag_name = forms.CharField(label="new tag name", max_length=50, required=False)
    new_tag_color = forms.CharField(label="color", max_length=6, required=False)

    def clean(self):
        cleaned_data = super(AddTagForm, self).clean()
        existing_tag = cleaned_data.get("existing_tag")
        new_tag_name = cleaned_data.get("new_tag_name")
        if not existing_tag:
            if not new_tag_name or not new_tag_name.strip():
                msg = "You must select an existing tag or enter a name for a new tag"
                self.add_error('existing_tag', msg)
                self.add_error('new_tag_name', msg)
            else:
                t = Tag(name=new_tag_name, slug=slugify(new_tag_name))
                try:
                    t.validate_unique()
                except ValidationError:
                    self.add_error('new_tag_name', "A tag with the same name or slug already exists")

    def _get_tag(self):
        tag = self.cleaned_data['existing_tag']
        if not tag:
            kwargs = {'name': self.cleaned_data.get('new_tag_name')}
            meta_business_unit = self._get_mbu()
            if meta_business_unit:
                kwargs['meta_business_unit'] = meta_business_unit
            new_tag_color = self.cleaned_data.get('new_tag_color')
            if new_tag_color:
                kwargs['color'] = new_tag_color
            tag = Tag(**kwargs)
            tag.save()
        return tag


class AddMBUTagForm(AddTagForm):
    restrict_new_tag_to_mbu = forms.BooleanField(label="restrict new tag to mbu", required=False)

    def __init__(self, *args, **kwargs):
        self.mbu = kwargs.pop('meta_business_unit')
        super(AddMBUTagForm, self).__init__(*args, **kwargs)
        etqs = Tag.objects.available_for_meta_business_unit(self.mbu)
        self.fields['existing_tag'].queryset = etqs.exclude(metabusinessunittag__meta_business_unit=self.mbu)

    def _get_mbu(self):
        if self.cleaned_data['restrict_new_tag_to_mbu']:
            return self.mbu

    def save(self):
        return MetaBusinessUnitTag.objects.get_or_create(meta_business_unit=self.mbu,
                                                         tag=self._get_tag())


class AddMachineTagForm(AddTagForm):
    new_tag_mbu = forms.ModelChoiceField(label="restricted to business unit",
                                         queryset=MetaBusinessUnit.objects.none(), required=False)

    def __init__(self, *args, **kwargs):
        self.machine = MetaMachine(kwargs.pop('machine_serial_number'))
        super(AddMachineTagForm, self).__init__(*args, **kwargs)
        self.fields['existing_tag'].queryset = Tag.objects.filter(id__in=[t.id for t in self.machine.available_tags()])
        self.fields['new_tag_mbu'].queryset = MetaBusinessUnit.objects.filter(
            id__in=self.machine.meta_business_unit_id_set
        )

    def _get_mbu(self):
        return self.cleaned_data.get('new_tag_mbu')

    def save(self, *args, **kwargs):
        return MachineTag.objects.get_or_create(serial_number=self.machine.serial_number,
                                                tag=self._get_tag())


class MacOSAppSearchForm(forms.Form):
    bundle_name = forms.CharField(label='Bundle name', max_length=64, required=False)
    source = forms.ModelChoiceField(queryset=Source.objects.current_macos_apps_sources(),
                                    required=False)
    sha_256 = forms.CharField(label="SHA 256", max_length=64, required=False,
                              validators=[validate_sha256],
                              help_text="sha 256 signature of the binary or "
                                        "one of the certificate in the chain")
    page = forms.IntegerField(required=False)

    def search(self, limit):
        args = []
        query = ("SELECT DISTINCT a.*, "
                 "string_agg(distinct src.name, ',  ') as source_names, count(*) OVER() AS full_count "
                 "FROM inventory_osxapp AS a "
                 "JOIN inventory_osxappinstance AS i ON (i.app_id = a.id) "
                 "JOIN inventory_machinesnapshot_osx_app_instances AS si ON (si.osxappinstance_id = i.id) "
                 "JOIN inventory_currentmachinesnapshot AS cms ON (si.machinesnapshot_id = cms.machine_snapshot_id) "
                 "JOIN inventory_source AS src ON (cms.source_id = src.id)")
        wheres = []
        # bundle name
        bundle_name = self.cleaned_data['bundle_name']
        if bundle_name:
            args.append(bundle_name)
            wheres.append("a.bundle_name ~* %s")
        # source
        source = self.cleaned_data['source']
        if source:
            args.append(source.id)
            wheres.append("src.id = %s")
        sha_256 = self.cleaned_data["sha_256"]
        if sha_256:
            args.insert(0, sha_256)
            query = (
                "WITH RECURSIVE filtered_certificates AS ("
                "SELECT id, signed_by_id "
                "FROM inventory_certificate "
                "WHERE sha_256 = %s "
                "UNION "
                "SELECT c.id, c.signed_by_id "
                "FROM inventory_certificate c "
                "INNER JOIN filtered_certificates fc ON fc.id = c.signed_by_id) "
                "{} "
                "LEFT JOIN filtered_certificates fc ON (i.signed_by_id = fc.id)"
            ).format(query)
            args.append(sha_256)
            wheres.append("(fc.id is NULL AND i.sha_256 = %s) OR (fc.id is not NULL)")
        if wheres:
            query = "{} WHERE {}".format(query,
                                         " AND ".join("({})".format(w) for w in wheres))
        # pagination / ordering
        page = self.cleaned_data['page']
        offset = (page - 1) * limit
        args.extend([offset, limit])
        query = ("{} GROUP BY a.id "
                 "ORDER BY a.bundle_name, a.bundle_id, a.bundle_version_str, a.bundle_version "
                 "OFFSET %s LIMIT %s").format(query)
        cursor = connection.cursor()
        cursor.execute(query, args)
        columns = [col[0] for col in cursor.description]
        results = []
        full_count = 0
        for t in cursor.fetchall():
            d = dict(zip(columns, t))
            full_count = d.pop('full_count')
            results.append(d)
        if full_count > offset + limit:
            next_page = page + 1
        else:
            next_page = None
        if page > 1:
            previous_page = page - 1
        else:
            previous_page = None
        total_pages = full_count // limit + 1
        return results, full_count, previous_page, next_page, total_pages

    def clean(self):
        cleaned_data = self.cleaned_data
        cleaned_data['page'] = max(1, int(cleaned_data.get('page') or 1))
        return cleaned_data


class EnrollmentSecretForm(forms.ModelForm):
    class Meta:
        model = EnrollmentSecret
        fields = ("meta_business_unit", "tags", "serial_numbers", "udids", "quota")

    def __init__(self, *args, **kwargs):
        self.no_restrictions = kwargs.pop("no_restrictions", False)
        self.meta_business_unit = kwargs.pop("meta_business_unit", None)
        super().__init__(*args, **kwargs)
        mbu_field = self.fields["meta_business_unit"]
        mbu_field.queryset = MetaBusinessUnit.objects.available_for_api_enrollment()
        if self.meta_business_unit:
            mbu_field.queryset = mbu_field.queryset.filter(pk=self.meta_business_unit.pk)
            mbu_field.initial = self.meta_business_unit.pk
            mbu_field.widget = forms.HiddenInput()
            self.fields['tags'].queryset = Tag.objects.available_for_meta_business_unit(self.meta_business_unit)
        if self.no_restrictions:
            for field_name in ("serial_numbers", "udids", "quota"):
                self.fields[field_name].widget = forms.HiddenInput()

    def clean(self):
        super().clean()
        meta_business_unit = self.cleaned_data["meta_business_unit"] or self.meta_business_unit
        if meta_business_unit:
            tag_set = set(self.cleaned_data['tags'])
            wrong_tag_set = tag_set - set(Tag.objects.available_for_meta_business_unit(meta_business_unit))
            if wrong_tag_set:
                raise forms.ValidationError(
                    "Tag{} {} not available for this business unit".format(
                        "" if len(wrong_tag_set) == 1 else "s",
                        ", ".join(str(t) for t in wrong_tag_set)
                    )
                )
        return self.cleaned_data

    def save(self, *args, **kwargs):
        commit = kwargs.pop("commit", True)
        kwargs["commit"] = False
        enrollment_secret = super().save(*args, **kwargs)
        if self.meta_business_unit:
            enrollment_secret.meta_business_unit = self.meta_business_unit
        if commit:
            enrollment_secret.save()
        return enrollment_secret
