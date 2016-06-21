from django import forms
from django.core.exceptions import ValidationError
from django.utils.text import slugify
from .models import MetaBusinessUnit, Source, MetaBusinessUnitTag, Tag, MetaMachine, MachineTag


class MachineSearchForm(forms.Form):
    serial_number = forms.CharField(label="serial number", max_length=32, required=False)
    name = forms.CharField(label="name", max_length=64, required=False)
    source = forms.ModelChoiceField(queryset=Source.objects.current_machine_snapshot_sources(),
                                    required=False,
                                    widget=forms.Select(attrs={'class': 'form-control'}))
    tag = forms.ChoiceField(choices=[],
                            required=False,
                            widget=forms.Select(attrs={'class': 'form-control'}))

    def clean_tag(self):
        if self.cleaned_data['tag']:
            return int(self.cleaned_data['tag'])
        else:
            return None

    def __init__(self, *args, **kwargs):
        super(MachineSearchForm, self).__init__(*args, **kwargs)
        self.fields['tag'].choices = [(t.id, str(t)) for t, _ in Tag.objects.used_in_inventory()]
        self.fields['tag'].choices.insert(0, ('', '--------'))


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
            id__in=[mbu.id for mbu in self.machine.meta_business_units()]
        )

    def _get_mbu(self):
        return self.cleaned_data.get('new_tag_mbu')

    def save(self, *args, **kwargs):
        return MachineTag.objects.get_or_create(serial_number=self.machine.serial_number,
                                                tag=self._get_tag())
