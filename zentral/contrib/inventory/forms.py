from datetime import datetime, timedelta
import json
from django import forms
from django.core.exceptions import ValidationError
from django.db import connection
from django.http import QueryDict
from django.urls import reverse
from django.utils.text import slugify
import jmespath
from zentral.utils.text import get_version_sort_key
from .conf import PLATFORM_CHOICES
from .models import (CurrentMachineSnapshot,
                     EnrollmentSecret,
                     MetaMachine,
                     MetaBusinessUnit, MetaBusinessUnitTag,
                     Source, Tag,
                     JMESPathCheck)
from .utils import (add_machine_tags,
                    AndroidAppFilter,
                    BundleFilter,
                    DebPackageFilter,
                    IOSAppFilter,
                    LastSeenFilter,
                    MSQuery,
                    ProgramFilter,
                    SourceFilter)


class MachineGroupSearchForm(forms.Form):
    template_name = "django/forms/search.html"

    name = forms.CharField(label="Name", max_length=64, required=False,
                           widget=forms.TextInput(attrs={"autofocus": True, "placeholder": "Name"}),)
    source = forms.ModelChoiceField(queryset=Source.objects.current_machine_group_sources(),
                                    required=False,
                                    empty_label='...',)


class MetaBusinessUnitSearchForm(forms.Form):
    template_name = "django/forms/search.html"

    name = forms.CharField(
        max_length=64,
        required=False,
        label='Name',
        widget=forms.TextInput(attrs={"autofocus": True, "placeholder": "Name"}),
        )
    source = forms.ModelChoiceField(
        queryset=Source.objects.current_business_unit_sources(),
        required=False,
        label='Source',
        empty_label='...',
        )
    tag = forms.ModelChoiceField(
        queryset=Tag.objects.distinct().filter(metabusinessunittag__isnull=False),
        required=False,
        label='Tag',
        empty_label='...',
        )


class MetaBusinessUnitForm(forms.ModelForm):

    api_enrollment = forms.BooleanField(label="API Enrollment", required=False,)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk and self.instance.api_enrollment_enabled():
            self.fields['api_enrollment'].initial = True
            self.fields['api_enrollment'].disabled = True

    class Meta:
        model = MetaBusinessUnit
        fields = ("name",)
        widgets = {"name": forms.TextInput}

    def save(self):
        self.instance.save()
        if self.cleaned_data.get("api_enrollment"):
            if not self.instance.api_enrollment_business_units().count():
                self.instance.create_enrollment_business_unit()
        return self.instance


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
        fields = ("meta_business_unit", "taxonomy", "name", "color")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.meta_business_unit:
            self.fields['meta_business_unit'].disabled = True
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
    existing_tag = forms.ModelChoiceField(label="Existing tag",
                                          queryset=Tag.objects.none(),
                                          required=False,
                                          empty_label='...')
    new_tag_name = forms.CharField(label="New tag name", required=False)
    new_tag_color = forms.CharField(label="Color", max_length=6, required=False)

    def clean(self):
        cleaned_data = super(AddTagForm, self).clean()
        existing_tag = cleaned_data.get("existing_tag")
        new_tag_name = cleaned_data.get("new_tag_name")
        if not existing_tag:
            if not new_tag_name or not new_tag_name.strip():
                if not self.has_error("existing_tag"):
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
    restrict_new_tag_to_mbu = forms.BooleanField(label="Restrict new tag to mbu", required=False)

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
    new_tag_mbu = forms.ModelChoiceField(label="Restricted to business unit",
                                         queryset=MetaBusinessUnit.objects.none(),
                                         required=False, empty_label='...')

    def __init__(self, *args, **kwargs):
        self.machine = MetaMachine(kwargs.pop('machine_serial_number'))
        self.request = kwargs.pop('request')
        super(AddMachineTagForm, self).__init__(*args, **kwargs)
        self.fields['existing_tag'].queryset = Tag.objects.filter(id__in=[t.id for t in self.machine.available_tags()])
        self.fields['new_tag_mbu'].queryset = MetaBusinessUnit.objects.filter(
            id__in=self.machine.meta_business_unit_id_set
        )

    def _get_mbu(self):
        return self.cleaned_data.get('new_tag_mbu')

    def save(self, *args, **kwargs):
        add_machine_tags(self.machine.serial_number, [self._get_tag()], self.request)


class BaseAppSearchForm(forms.Form):
    source = forms.ModelChoiceField(queryset=Source.objects.current_machine_snapshot_sources(),
                                    required=False,
                                    empty_label='...',)
    last_seen = forms.ChoiceField(
        choices=(("1d", "24 hours"),
                 ("7d", "7 days"),
                 ("14d", "14 days"),
                 ("30d", "30 days"),
                 ("45d", "45 days"),
                 ("90d", "90 days")),
        initial="1d",
        required=False,
    )
    order = forms.ChoiceField(choices=[], required=False, widget=forms.HiddenInput())
    action = forms.CharField(required=False, widget=forms.HiddenInput())
    order_mapping = {}
    default_order = None
    title = None
    app_headers = None
    version_headers = None
    version_sort_keys = ("version",)

    def __init__(self, *args, **kwargs):
        self.export = kwargs.pop("export", False)
        super().__init__(*args, **kwargs)
        self.fields["order"].choices = [(f"{k}-{d}", f"{k}-{d}") for k in self.order_mapping for d in ("a", "d")]

    def fetch_results(self):
        return self.is_valid() and self.cleaned_data.get("action") == "search"

    def _get_current_order(self):
        try:
            order_attr_abv, order_dir = self.cleaned_data["order"].split("-")
            return self.order_mapping[order_attr_abv], "ASC" if order_dir == "a" else "DESC"
        except (KeyError, TypeError, ValueError):
            return self.default_order

    def get_header_label_and_link(self, attr, label):
        if not attr:
            return label, None
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

    def get_table_headers(self):
        table_headers = []
        for _, order_attr, ui_header, label in self.app_headers:
            if ui_header:
                table_headers.append(self.get_header_label_and_link(order_attr, label))
        for _, ui_header, label in self.version_headers:
            if ui_header:
                table_headers.append(self.get_header_label_and_link(None, label))
        table_headers.append(self.get_header_label_and_link("ms_count", "Machines"))
        return table_headers

    def iter_export_headers(self):
        for attr, _, _, label in self.app_headers:
            yield attr, label
        for attr, _, label in self.version_headers:
            yield attr, label
        yield "ms_count", "Machines"

    def get_source(self):
        return self.cleaned_data.get("source")

    def get_last_seen(self):
        last_seen = self.cleaned_data.get("last_seen")
        if last_seen:
            return datetime.utcnow() - timedelta(days=int(last_seen.replace("d", "")))

    def get_ms_query_filters(self, result, version=None):
        """Return a list of MSQuery filters for an app or one of its versions

        Used in the get_link method to build a link for an app and its versions.
        Override to add the correct filter.
        """
        filters = []
        if version:
            source_pk = version.get("source_pk")
            if source_pk:
                filters.append((SourceFilter, {"value": source_pk}))
        else:
            source = self.get_source()
            if source:
                filters.append((SourceFilter, {"value": source.pk}))
        last_seen = self.cleaned_data.get("last_seen")
        if last_seen:
            filters.append((LastSeenFilter, {"value": last_seen}))
        return filters

    def get_link(self, result, version=None):
        """Used to add a link to the inventory index for an app and its versions"""
        ms_query = MSQuery()
        for filter_class, filter_kwargs in self.get_ms_query_filters(result, version):
            ms_query.force_filter(filter_class, **filter_kwargs)
        return "{}{}".format(reverse("inventory:index"), ms_query.get_canonical_url())

    def get_version_sort_key(self, version):
        sort_key = []
        for attr in self.version_sort_keys:
            val = version.get(attr)
            if val:
                sort_key.append(get_version_sort_key(val))
        return sort_key

    def get_query_and_args(self):
        raise NotImplementedError

    def iter_results(self, page=None, limit=None):
        query, args = self.get_query_and_args()
        # pagination
        if page and limit:
            offset = (page - 1) * limit
            args.extend([offset, limit])
            query += " offset %s limit %s"
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
                if not self.export:
                    d["link"] = self.get_link(d)
                self.full_count = d.pop('full_count')
                versions = json.loads(d.pop('versions'))
                if not self.export:
                    for version in versions:
                        version["link"] = self.get_link(d, version)
                versions.sort(key=lambda d: self.get_version_sort_key(d), reverse=True)
                d['versions'] = versions
                yield d

    def iter_export_rows(self):
        attrs = list(attr for attr, _ in self.iter_export_headers())
        for result in self.iter_results():
            versions = result.pop("versions")
            yield [result.get(attr) for attr in attrs]
            for version in versions:
                row = result.copy()
                row.update(version)
                yield [row.get(attr) for attr in attrs]

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
        super().clean()
        cleaned_data = self.cleaned_data
        cleaned_data['page'] = max(1, int(cleaned_data.get('page') or 1))
        return cleaned_data


class AndroidAppSearchForm(BaseAppSearchForm):
    template_name = "django/forms/search.html"

    display_name = forms.CharField(label="Name", max_length=64,
                                   widget=forms.TextInput(attrs={"autofocus": True, "placeholder": "Name"}),
                                   required=False)
    order_mapping = {"dn": "display_name",
                     "mc": "ms_count"}
    default_order = ("display_name", "ASC")
    title = "Android apps"
    app_headers = (
        ("display_name", "display_name", True, "Name"),
    )
    version_headers = (
        ("version_name", False, "Version name"),
        ("version_code", False, "Version code"),
        ("source_name", True, "Source"),
    )
    version_sort_keys = ("version_name", "version_code")

    field_order = ("display_name", "source", "last_seen",)

    def get_ms_query_filters(self, result, version=None):
        filters = super().get_ms_query_filters(result, version)
        filter_kwargs = {"display_name": result["display_name"]}
        if version:
            filter_kwargs["value"] = version["pk"]
        filters.append((AndroidAppFilter, filter_kwargs))
        return filters

    def get_query_and_args(self):
        args = []

        # filtering
        wheres = []
        display_name = self.cleaned_data.get("display_name")
        if display_name:
            args.append("%{}%".format(connection.ops.prep_for_like_query(display_name)))
            wheres.append("UPPER(aa.display_name) LIKE UPPER(%s)")
        source = self.get_source()
        if source:
            args.append(source.id)
            wheres.append("s.id = %s")
        last_seen = self.get_last_seen()
        if last_seen:
            args.append(last_seen)
            wheres.append("cms.last_seen >= %s")
        if wheres:
            wheres_str = "where {}".format(" and ".join(wheres))
        else:
            wheres_str = ""

        # ordering
        order_attr, order_dir = self._get_current_order()
        order_str = f"{order_attr} {order_dir}"
        if order_attr == "ms_count":
            order_str = f"{order_str}, display_name ASC"

        query = (
            "with aaa as ("
            "  select aa.id, aa.display_name, aa.version_name, aa.version_code, s.name source_name, s.id source_id,"
            "  sum(count(*)) over (partition by aa.display_name) name_ms_count,"
            "  count(*) version_ms_count"
            "  from inventory_androidapp as aa"
            "  join inventory_machinesnapshot_android_apps as msaa on (aa.id = msaa.androidapp_id)"
            "  join inventory_currentmachinesnapshot as cms on (msaa.machinesnapshot_id = cms.machine_snapshot_id)"
            "  join inventory_source as s on (cms.source_id = s.id)"
            f" {wheres_str}"
            "  group by aa.id, aa.display_name, aa.version_name, aa.version_code, s.name, s.id"
            ") select display_name, name_ms_count ms_count,"
            "jsonb_agg("
            "  jsonb_build_object("
            "    'pk', id,"
            "    'version_name', version_name,"
            "    'version_code', version_code,"
            "    'source_name', source_name,"
            "    'source_pk', source_id,"
            "    'ms_count', version_ms_count"
            ")) versions,"
            "count(*) over () as full_count "
            "from aaa "
            "group by display_name, ms_count "
            f"order by {order_str}"
        )
        return query, args


class DebPackageSearchForm(BaseAppSearchForm):
    template_name = "django/forms/search.html"

    name = forms.CharField(label="Package name", max_length=64,
                           widget=forms.TextInput(attrs={"autofocus": True, "placeholder": "Package name"}),
                           required=False)
    order_mapping = {"n": "name",
                     "mc": "ms_count"}
    default_order = ("name", "ASC")
    title = "Debian packages"
    app_headers = (
        ("name", "name", True, "Package"),
    )
    version_headers = (
        ("version", False, "Version"),
        ("source_name", True, "Source"),
    )

    field_order = ("name", "source", "last_seen",)

    def get_ms_query_filters(self, result, version=None):
        filters = super().get_ms_query_filters(result, version)
        filter_kwargs = {"name": result["name"]}
        if version:
            filter_kwargs["value"] = version["pk"]
        filters.append((DebPackageFilter, filter_kwargs))
        return filters

    def get_query_and_args(self):
        args = []

        # filtering
        wheres = []
        name = self.cleaned_data.get("name")
        if name:
            args.append("%{}%".format(connection.ops.prep_for_like_query(name)))
            wheres.append("UPPER(dp.name) LIKE UPPER(%s)")
        source = self.get_source()
        if source:
            args.append(source.id)
            wheres.append("s.id = %s")
        last_seen = self.get_last_seen()
        if last_seen:
            args.append(last_seen)
            wheres.append("cms.last_seen >= %s")
        if wheres:
            wheres_str = "where {}".format(" and ".join(wheres))
        else:
            wheres_str = ""

        # ordering
        order_attr, order_dir = self._get_current_order()
        order_str = f"{order_attr} {order_dir}"
        if order_attr == "ms_count":
            order_str = f"{order_str}, name ASC"

        query = (
            "with adp as ("
            "  select dp.id, dp.name, dp.version, s.name source_name, s.id source_id,"
            "  sum(count(*)) over (partition by dp.name) name_ms_count,"
            "  count(*) version_ms_count"
            "  from inventory_debpackage as dp"
            "  join inventory_machinesnapshot_deb_packages as msdp on (dp.id = msdp.debpackage_id)"
            "  join inventory_currentmachinesnapshot as cms on (msdp.machinesnapshot_id = cms.machine_snapshot_id)"
            "  join inventory_source as s on (cms.source_id = s.id)"
            f" {wheres_str}"
            "  group by dp.id, dp.name, dp.version, s.name, s.id"
            ") select name, name_ms_count ms_count,"
            "jsonb_agg("
            "  jsonb_build_object("
            "    'pk', id,"
            "    'version', version,"
            "    'source_name', source_name,"
            "    'source_pk', source_id,"
            "    'ms_count', version_ms_count"
            ")) versions,"
            "count(*) over () as full_count "
            "from adp "
            "group by name, ms_count "
            f"order by {order_str}"
        )
        return query, args


class IOSAppSearchForm(BaseAppSearchForm):
    template_name = "django/forms/search.html"

    name = forms.CharField(label="Name", max_length=64,
                           widget=forms.TextInput(attrs={"autofocus": True, "placeholder": "Name"}),
                           required=False)
    order_mapping = {"n": "name",
                     "mc": "ms_count"}
    default_order = ("name", "ASC")
    title = "iOS apps"
    app_headers = (
        ("name", "name", True, "Name"),
        ("identifier", None, False, "Identifier"),
    )
    version_headers = (
        ("version", False, "Version"),
        ("short_version", False, "Short version"),
        ("source_name", True, "Source"),
    )
    version_sort_keys = ("version", "short_version")

    field_order = ("name", "source", "last_seen",)

    def get_ms_query_filters(self, result, version=None):
        filters = super().get_ms_query_filters(result, version)
        filter_kwargs = {"name": result["name"]}
        if version:
            filter_kwargs["value"] = version["pk"]
        filters.append((IOSAppFilter, filter_kwargs))
        return filters

    def get_query_and_args(self):
        args = []

        # filtering
        wheres = []
        name = self.cleaned_data.get("name")
        if name:
            args.append("%{}%".format(connection.ops.prep_for_like_query(name)))
            wheres.append("UPPER(ia.name) LIKE UPPER(%s)")
        source = self.get_source()
        if source:
            args.append(source.id)
            wheres.append("s.id = %s")
        last_seen = self.get_last_seen()
        if last_seen:
            args.append(last_seen)
            wheres.append("cms.last_seen >= %s")
        if wheres:
            wheres_str = "where {}".format(" and ".join(wheres))
        else:
            wheres_str = ""

        # ordering
        order_attr, order_dir = self._get_current_order()
        order_str = f"{order_attr} {order_dir}"
        if order_attr == "ms_count":
            order_str = f"{order_str}, name ASC"

        query = (
            "with aia as ("
            "  select ia.id, ia.name, ia.identifier, ia.version, ia.short_version, s.name source_name, s.id source_id,"
            "  sum(count(*)) over (partition by ia.name, ia.identifier) name_ms_count,"
            "  count(*) version_ms_count"
            "  from inventory_iosapp as ia"
            "  join inventory_machinesnapshot_ios_apps as msia on (ia.id = msia.iosapp_id)"
            "  join inventory_currentmachinesnapshot as cms on (msia.machinesnapshot_id = cms.machine_snapshot_id)"
            "  join inventory_source as s on (cms.source_id = s.id)"
            f" {wheres_str}"
            "  group by ia.id, ia.name, ia.identifier, ia.version, ia.short_version, s.name, s.id"
            ") select name, identifier, name_ms_count ms_count,"
            "jsonb_agg("
            "  jsonb_build_object("
            "    'pk', id,"
            "    'version', version,"
            "    'short_version', short_version,"
            "    'source_name', source_name,"
            "    'source_pk', source_id,"
            "    'ms_count', version_ms_count"
            ")) versions,"
            "count(*) over () as full_count "
            "from aia "
            "group by name, identifier, ms_count "
            f"order by {order_str}"
        )
        return query, args


class MacOSAppSearchForm(BaseAppSearchForm):
    template_name = "django/forms/search.html"

    bundle = forms.CharField(label='Bundle', max_length=64,
                             widget=forms.TextInput(attrs={"autofocus": True, "placeholder": "Bundle"}),
                             required=False)
    order_mapping = {"bn": "bundle_name",
                     "mc": "ms_count"}
    default_order = ("bundle_name", "ASC")
    title = "macOS apps"
    app_headers = (
        ("bundle_name", "bundle_name", True, "Bundle"),
        ("bundle_id", None, False, "Bundle ID"),
    )
    version_headers = (
        ("bundle_version", False, "Bundle version"),
        ("bundle_version_str", False, "Bundle version str"),
        ("source_name", True, "Source"),
    )
    version_sort_keys = ("bundle_version", "bundle_version_str")

    field_order = ("bundle", "source", "last_seen",)

    def get_ms_query_filters(self, result, version=None):
        filters = super().get_ms_query_filters(result, version)
        bundle_name = result["bundle_name"]
        bundle_id = result["bundle_id"]
        if bundle_name or bundle_id:
            if bundle_name:
                filter_kwargs = {"bundle_name": bundle_name}
            else:
                filter_kwargs = {"bundle_id": bundle_id}
            if version:
                filter_kwargs["value"] = version["pk"]
            filters.append((BundleFilter, filter_kwargs))
        return filters

    def get_query_and_args(self):
        args = []

        # filtering
        wheres = []
        bundle = self.cleaned_data.get("bundle")
        if bundle:
            prepared_bundle = "%{}%".format(connection.ops.prep_for_like_query(bundle))
            args.append(prepared_bundle)
            args.append(prepared_bundle)
            wheres.append("(UPPER(a.bundle_id) LIKE UPPER(%s) OR UPPER(a.bundle_name) LIKE UPPER(%s))")
        source = self.get_source()
        if source:
            args.append(source.id)
            wheres.append("s.id = %s")
        last_seen = self.get_last_seen()
        if last_seen:
            args.append(last_seen)
            wheres.append("cms.last_seen >= %s")
        if wheres:
            wheres_str = "where {}".format(" and ".join(wheres))
        else:
            wheres_str = ""

        # ordering
        order_attr, order_dir = self._get_current_order()
        order_str = f"{order_attr} {order_dir}"
        if order_attr == "ms_count":
            order_str = f"{order_str}, bundle_name ASC"

        query = (
            "with ama as ("
            "  select a.id, a.bundle_id, a.bundle_name, a.bundle_version, a.bundle_version_str,"
            "  s.name source_name, s.id source_id,"
            "  sum(count(*)) over (partition by a.bundle_id, a.bundle_name) bundle_ms_count,"
            "  count(*) version_ms_count"
            "  from inventory_osxapp as a"
            "  join inventory_osxappinstance as ai on (ai.app_id = a.id)"
            "  join inventory_machinesnapshot_osx_app_instances as msoai on(msoai.osxappinstance_id = ai.id)"
            "  join inventory_currentmachinesnapshot as cms on (msoai.machinesnapshot_id = cms.machine_snapshot_id)"
            "  join inventory_source as s on (cms.source_id = s.id)"
            f" {wheres_str}"
            "  group by a.id, a.bundle_id, a.bundle_name, a.bundle_version, a.bundle_version_str, s.name, s.id"
            ") select bundle_id, bundle_name, bundle_ms_count ms_count,"
            "jsonb_agg("
            "jsonb_build_object("
            "  'pk', id,"
            "  'bundle_version', bundle_version,"
            "  'bundle_version_str', bundle_version_str,"
            "  'source_name', source_name,"
            "  'source_pk', source_id,"
            "  'ms_count', version_ms_count"
            ")) versions,"
            "count(*) over () as full_count "
            "from ama "
            "group by bundle_id, bundle_name, ms_count "
            f"order by {order_str}"
        )
        return query, args


class ProgramsSearchForm(BaseAppSearchForm):
    template_name = "django/forms/search.html"

    name = forms.CharField(label='Name', max_length=64,
                           widget=forms.TextInput(attrs={"autofocus": True, "placeholder": "Name"}),
                           required=False)
    order_mapping = {"n": "name",
                     "mc": "ms_count"}
    default_order = ("name", "ASC")
    title = "Programs"
    app_headers = (
        ("name", "name", True, "Name"),
        ("identifying_number", None, False, "Identifying number"),
    )
    version_headers = (
        ("version", False, "Version"),
        ("source_name", True, "Source"),
    )

    field_order = ("name", "source", "last_seen",)

    def get_ms_query_filters(self, result, version=None):
        filters = super().get_ms_query_filters(result, version)
        filter_kwargs = {"name": result["name"]}
        if version:
            filter_kwargs["value"] = version["pk"]
        filters.append((ProgramFilter, filter_kwargs))
        return filters

    def get_query_and_args(self):
        args = []

        # filtering
        wheres = []
        name = self.cleaned_data.get("name")
        if name:
            args.append("%{}%".format(connection.ops.prep_for_like_query(name)))
            wheres.append("UPPER(p.name) LIKE UPPER(%s)")
        source = self.get_source()
        if source:
            args.append(source.id)
            wheres.append("s.id = %s")
        last_seen = self.get_last_seen()
        if last_seen:
            args.append(last_seen)
            wheres.append("cms.last_seen >= %s")
        if wheres:
            wheres_str = "where {}".format(" and ".join(wheres))
        else:
            wheres_str = ""

        # ordering
        order_attr, order_dir = self._get_current_order()
        order_str = f"{order_attr} {order_dir}"
        if order_attr == "ms_count":
            order_str = f"{order_str}, name ASC"

        query = (
            "with ap as ("
            "  select p.id, p.name, p.identifying_number, p.version,"
            "  s.name source_name, s.id source_id,"
            "  sum(count(*)) over (partition by p.name, p.identifying_number) program_ms_count,"
            "  count(*) version_ms_count"
            "  from inventory_program as p"
            "  join inventory_programinstance as pi on (pi.program_id = p.id)"
            "  join inventory_machinesnapshot_program_instances as mspi on(mspi.programinstance_id = pi.id)"
            "  join inventory_currentmachinesnapshot as cms on (mspi.machinesnapshot_id = cms.machine_snapshot_id)"
            "  join inventory_source as s on (cms.source_id = s.id)"
            f" {wheres_str}"
            "  group by p.id, p.name, p.identifying_number, p.version, s.name, s.id"
            ") select name, identifying_number, program_ms_count ms_count,"
            "jsonb_agg("
            "jsonb_build_object("
            "  'pk', id,"
            "  'version', version,"
            "  'source_name', source_name,"
            "  'source_pk', source_id,"
            "  'ms_count', version_ms_count"
            ")) versions,"
            "count(*) over () as full_count "
            "from ap "
            "group by name, identifying_number, ms_count "
            f"order by {order_str}"
        )
        return query, args


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
        meta_business_unit = self.cleaned_data.get("meta_business_unit") or self.meta_business_unit
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
