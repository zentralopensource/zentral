from django import forms
from django.core.exceptions import ValidationError
from django.db import connection
from django.http import QueryDict
from django.utils.text import slugify
import jmespath
from .conf import PLATFORM_CHOICES
from .models import (CurrentMachineSnapshot,
                     EnrollmentSecret,
                     MachineTag, MetaMachine,
                     MetaBusinessUnit, MetaBusinessUnitTag,
                     Source, Tag,
                     JMESPathCheck)


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

    def clean_name(self):
        name = self.cleaned_data.get("name")
        if name:
            if Tag.objects.filter(name=name).exists():
                raise ValidationError("A tag with this name already exists.")
            slug = slugify(name)
            if Tag.objects.filter(slug=slug).exists():
                raise ValidationError("A tag with a conflicting slug already exists.")
        return name

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

    def clean_name(self):
        name = self.cleaned_data.get("name")
        if name:
            qs = Tag.objects.all()
            if self.instance.pk:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.filter(name=name).exists():
                raise ValidationError("A tag with this name already exists.")
            slug = slugify(name)
            if qs.filter(slug=slug).exists():
                raise ValidationError("A tag with a conflicting slug already exists.")
        return name


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
    bundle_name = forms.CharField(label='Bundle name', max_length=64,
                                  widget=forms.TextInput(attrs={"autofocus": "true"}))
    source = forms.ModelChoiceField(queryset=Source.objects.current_machine_snapshot_sources(),
                                    required=False)
    order = forms.ChoiceField(choices=[], required=False)
    order_mapping = {"bn": "bundle_name",
                     "mc": "machine_count"}

    def __init__(self, *args, **kwargs):
        export = kwargs.pop("export", False)
        super().__init__(*args, **kwargs)
        self.fields["order"].choices = [(f"{k}-{d}", f"{k}-{d}") for k in self.order_mapping for d in ("a", "d")]
        if export:
            self.fields["bundle_name"].required = False

    def _get_current_order(self):
        try:
            order_attr_abv, order_dir = self.cleaned_data["order"].split("-")
            return self.order_mapping[order_attr_abv], "ASC" if order_dir == "a" else "DESC"
        except (KeyError, TypeError, ValueError):
            return "bundle_name", "ASC"

    def get_header_label_and_link(self, attr, label):
        reversed_order_mapping = {v: k for k, v in self.order_mapping.items()}
        link = None
        attr_abv = reversed_order_mapping.get(attr)
        if attr_abv:
            order_attr, order_dir = self._get_current_order()
            if order_attr == attr:
                label = "{} {}".format("↑" if order_dir == "ASC" else "↓", label)
                # reverse order link
                order = "{}-{}".format(attr_abv, "d" if order_dir == "ASC" else "a")
            else:
                # ASC order link
                order = f"{attr_abv}-a"
            qd = QueryDict(mutable=True)
            qd.update({k: v for k, v in self.data.items() if v})
            qd["order"] = order
            link = "?{}".format(qd.urlencode())
        return label, link

    def iter_results(self, page=None, limit=None):
        args = []
        query = ("SELECT a.id, a.bundle_id, a.bundle_name, a.bundle_version, a.bundle_version_str, "
                 "string_agg(distinct src.name, ',  ') as source_names, "
                 "count(distinct cms.serial_number) as machine_count, "
                 "count(*) over () as full_count "
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
        if wheres:
            query = "{} WHERE {}".format(query, " AND ".join(f"({w})" for w in wheres))
        # ordering
        order_attr, order_dir = self._get_current_order()
        order_str = f"{order_attr} {order_dir}"
        if order_attr == "machine_count":
            order_str = f"{order_str}, a.bundle_name ASC"
        query = (f"{query} GROUP BY a.id, a.bundle_id, a.bundle_name, a.bundle_version, a.bundle_version_str "
                 f"ORDER BY {order_str}, a.bundle_id, a.bundle_version_str, a.bundle_version")
        # pagination
        if page and limit:
            offset = (page - 1) * limit
            args.extend([offset, limit])
            query += " OFFSET %s LIMIT %s"
        # execute
        cursor = connection.cursor()
        cursor.execute(query, args)
        columns = [col[0] for col in cursor.description]
        self.full_count = 0
        while True:
            results = cursor.fetchmany(size=2000)
            if not results:
                break
            for t in results:
                d = dict(zip(columns, t))
                self.full_count = d.pop('full_count')
                yield d

    def search(self, page=1, limit=50):
        page = max(1, page)
        limit = max(1, limit)
        results = list(self.iter_results(page, limit))
        if self.full_count > page * limit:
            next_page = page + 1
        else:
            next_page = None
        if page > 1:
            previous_page = page - 1
        else:
            previous_page = None
        total_pages, rest = divmod(self.full_count, limit)
        if rest or total_pages == 0:
            total_pages += 1
        return results, self.full_count, previous_page, next_page, total_pages

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
        self.no_serial_numbers = kwargs.pop("no_serial_numbers", False)
        self.no_udids = kwargs.pop("no_udids", False)
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
        else:
            if self.no_serial_numbers:
                self.fields["serial_numbers"].widget = forms.HiddenInput()
            if self.no_udids:
                self.fields["udids"].widget = forms.HiddenInput()

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


# jmespath check


class PlatformsWidget(forms.CheckboxSelectMultiple):
    def __init__(self, attrs=None, choices=()):
        super().__init__(attrs, choices=PLATFORM_CHOICES)

    def format_value(self, value):
        if isinstance(value, str) and value:
            value = [v.strip() for v in value.split(",")]
        return super().format_value(value)


class JMESPathCheckForm(forms.ModelForm):
    class Meta:
        model = JMESPathCheck
        fields = ("source_name", "platforms", "tags", "jmespath_expression")
        widgets = {"source_name": forms.TextInput,
                   "platforms": PlatformsWidget}

    def clean_platforms(self):
        platforms = self.cleaned_data.get("platforms")
        if platforms is not None:
            if len(platforms) < 1:
                raise ValidationError("At least one platform must be selected")
        return platforms

    def clean_jmespath_expression(self):
        exp = self.cleaned_data.get("jmespath_expression")
        if exp:
            try:
                jmespath.compile(exp)
            except Exception:
                raise ValidationError("Invalid JMESPath expression")
        return exp


class JMESPathCheckDevToolForm(forms.Form):
    source = forms.ModelChoiceField(queryset=Source.objects.all())
    serial_number = forms.CharField(min_length=3, max_length=256)
    jmespath_expression = forms.CharField(widget=forms.Textarea(attrs={"rows": 3}))

    def clean_jmespath_expression(self):
        exp = self.cleaned_data.get("jmespath_expression")
        if exp:
            try:
                self.cleaned_data["compiled_jmespath"] = jmespath.compile(exp)
            except Exception:
                raise ValidationError("Invalid JMESPath expression")
        return exp

    def clean(self):
        cleaned_data = super().clean()
        serial_number = cleaned_data.get("serial_number")
        source = cleaned_data.get("source")
        if serial_number and source:
            try:
                cms = (
                    CurrentMachineSnapshot.objects.select_related("machine_snapshot")
                                                  .get(serial_number=serial_number, source=source)
                )
            except CurrentMachineSnapshot.DoesNotExist:
                self.add_error("serial_number", "Current machine with this serial number for this source not found")
            else:
                cleaned_data["tree"] = cms.machine_snapshot.serialize()
                compiled_jmespath = cleaned_data.get("compiled_jmespath")
                if compiled_jmespath:
                    try:
                        cleaned_data["result"] = compiled_jmespath.search(cleaned_data["tree"])
                    except Exception:
                        self.add_error("jmespath_expression", "Evaluation error")
                    else:
                        if not isinstance(cleaned_data["result"], bool):
                            self.add_error("jmespath_expression", "Result is not a boolean")
        return cleaned_data
