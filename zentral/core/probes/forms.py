from django import forms
from django.db.models import Q
from django.utils.text import slugify
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from zentral.contrib.inventory.conf import PLATFORM_CHOICES, TYPE_CHOICES
from zentral.utils.forms import CommaSeparatedQuotedStringField
from .base import BaseProbe
from .models import ProbeSource
from . import probe_classes


class ProbeSearchForm(forms.Form):
    q = forms.CharField(label="Query", required=False,
                        widget=forms.TextInput(attrs={"placeholder": "Keywords…"}))
    model = forms.ChoiceField(label="Model", choices=[], required=False)
    event_type = forms.ChoiceField(label="Event type", choices=[], required=False)
    status = forms.ChoiceField(label="Status",
                               choices=(("", "----"),
                                        ("INACTIVE", "Inactive"),
                                        ("ACTIVE", "Active")),
                               required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["model"].choices = [("", "----")] + ProbeSource.objects.current_models()
        self.fields["event_type"].choices = [("", "----")] + ProbeSource.objects.current_event_types()

    def get_queryset(self):
        cleaned_data = self.cleaned_data
        qs = ProbeSource.objects.all()
        q = cleaned_data.get("q")
        if q:
            qs = qs.filter(Q(name__icontains=q)
                           | Q(description__icontains=q)
                           | Q(body__icontains=q))
        model = cleaned_data.get("model")
        if model:
            qs = qs.filter(model=model)
        event_type = cleaned_data.get("event_type")
        if event_type:
            qs = qs.filter(event_types__contains=[event_type])
        status = cleaned_data.get("status")
        if status:
            qs = qs.filter(status=status)
        return qs

    def is_initial(self):
        return {k: v for k, v in self.cleaned_data.items() if v} == {'status': 'ACTIVE'}


class InventoryFilterForm(forms.Form):
    meta_business_units = forms.ModelMultipleChoiceField(queryset=MetaBusinessUnit.objects.all(),
                                                         label="business units",
                                                         required=False)
    tags = forms.ModelMultipleChoiceField(queryset=Tag.objects.all(),
                                          required=False)
    platforms = forms.MultipleChoiceField(choices=PLATFORM_CHOICES,
                                          required=False)
    types = forms.MultipleChoiceField(choices=TYPE_CHOICES,
                                      required=False)

    def clean(self):
        if not list(v for _, v in self.cleaned_data.items() if v):
            raise forms.ValidationError("You must specify at least one of the sub filters")
        return self.cleaned_data

    def get_filter_d(self):
        filter_d = self.cleaned_data.copy()
        for field_name, filter_attr in (("meta_business_units", "meta_business_unit_ids"),
                                        ("tags", "tag_ids")):
            value = filter_d.pop(field_name)
            if value:
                filter_d[filter_attr] = [o.id for o in value]
        for filter_attr in ("platforms", "types"):
            if not filter_d.get(filter_attr):
                filter_d.pop(filter_attr, None)
        return filter_d

    @staticmethod
    def get_initial(inventory_filter):
        initial_d = {}
        for field_name, filter_attr in (("meta_business_units", "meta_business_unit_ids"),
                                        ("tags", "tag_ids"),
                                        ("platforms", "platforms"),
                                        ("types", "types")):
            value = getattr(inventory_filter, filter_attr, None)
            if value:
                initial_d[field_name] = value
        return initial_d


class MetadataFilterForm(forms.Form):
    event_tags = forms.MultipleChoiceField(label="event tags", choices=[], required=False)
    event_types = forms.MultipleChoiceField(label="event types", choices=[], required=False,
                                            widget=forms.SelectMultiple(attrs={"size": 10}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from zentral.core.events import event_tags, event_types
        self.fields["event_tags"].choices = sorted((et, et.replace("_", " ").capitalize())
                                                   for et in event_tags.keys())
        self.fields["event_types"].choices = sorted((et, e.get_event_type_display())
                                                    for et, e in event_types.items()
                                                    if et != "base")

    def clean(self):
        cleaned_data = self.cleaned_data
        event_type = cleaned_data.get("event_types")
        event_tags = cleaned_data.get("event_tags")
        if not event_type and not event_tags:
            raise forms.ValidationError("Choose at least one event type or one tag.")
        return cleaned_data

    def get_filter_d(self):
        filter_d = {}
        for attr in ("event_tags", "event_types"):
            value = self.cleaned_data.get(attr)
            if value:
                filter_d[attr] = value
        return filter_d

    @staticmethod
    def get_initial(metadata_filter):
        initial_d = {}
        for attr in ("event_tags", "event_types"):
            val = getattr(metadata_filter, attr, None)
            if val:
                if isinstance(val, set):
                    val = list(val)
                initial_d[attr] = val
        return initial_d


class PayloadFilterItemForm(forms.Form):
    attribute = forms.CharField(
        widget=forms.TextInput(attrs={'placeholder': 'Name of the payload attribute',
                                      'size': '33%'}))
    values = CommaSeparatedQuotedStringField(
        widget=forms.TextInput(attrs={'placeholder': 'Comma separated value list',
                                      'size': '33%'}))


class BasePayloadFilterFormSet(forms.BaseFormSet):
    def get_filter_d(self):
        filter_d = {}
        for item_cleaned_data in self.cleaned_data:
            if not item_cleaned_data.get("DELETE"):
                filter_d[item_cleaned_data["attribute"]] = item_cleaned_data["values"]
        return filter_d

    @staticmethod
    def get_initial(payload_filter):
        initial = []
        for key, val in payload_filter.items.items():
            initial.append({"attribute": key, "values": val})
        return initial

PayloadFilterFormSet = forms.formset_factory(PayloadFilterItemForm,
                                             formset=BasePayloadFilterFormSet,
                                             min_num=1, max_num=10, extra=0, can_delete=True)


class BaseCreateProbeForm(forms.Form):
    model = BaseProbe
    name = forms.CharField(max_length=255)

    def clean_name(self):
        name = self.cleaned_data.get("name")
        if name and ProbeSource.objects.filter(Q(name=name) | Q(slug=slugify(name))).count() > 0:
            raise forms.ValidationError('A probe with this name already exists')
        return name

    def get_probe_source_model(self):
        for k, v in probe_classes.items():
            if v == self.model:
                return k

    def save(self):
        ps = ProbeSource(model=self.get_probe_source_model(),
                         name=self.cleaned_data["name"],
                         body=self.get_body())
        ps.save()
        return ps


class CreateProbeForm(BaseCreateProbeForm, MetadataFilterForm):
    field_order = ("name", "event_type")

    def get_body(self):
        return {"filters": {"metadata": [self.get_filter_d()]}}
