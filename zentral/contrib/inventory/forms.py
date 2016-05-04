from django import forms
from .models import MetaBusinessUnit, Source, MetaBusinessUnitTag, Tag, Machine, MachineTag


class MachineSearchForm(forms.Form):
    serial_number = forms.CharField(label="serial number", max_length=32, required=False)
    name = forms.CharField(label="name", max_length=64, required=False)
    source = forms.ModelChoiceField(queryset=Source.objects.current_machine_snapshot_sources(),
                                    required=False,
                                    widget=forms.Select(attrs={'class': 'form-control'}))


class MachineGroupSearchForm(forms.Form):
    name = forms.CharField(label="name", max_length=64, required=False)
    source = forms.ModelChoiceField(queryset=Source.objects.current_machine_group_sources(),
                                    required=False,
                                    widget=forms.Select(attrs={'class': 'form-control'}))


class MetaBusinessUnitSearchForm(forms.Form):
    name = forms.CharField(label="name", max_length=64, required=False)
    source = forms.ModelChoiceField(queryset=Source.objects.current_business_unit_sources(),
                                    required=False,
                                    widget=forms.Select(attrs={'class': 'form-control'}))


class MergeMBUForm(forms.Form):
    mbu = forms.ModelMultipleChoiceField(queryset=MetaBusinessUnit.objects.all())
    dest_mbu = forms.ModelChoiceField(queryset=MetaBusinessUnit.objects.all())

    def merge(self):
        dest_mbu = self.cleaned_data['dest_mbu']
        for mbu in self.cleaned_data['mbu']:
            if mbu == dest_mbu:
                continue
            for bu in mbu.businessunit_set.all():
                bu.set_meta_business_unit(dest_mbu)
            mbu.delete()
        return dest_mbu


class MBUAPIEnrollmentForm(forms.ModelForm):
    class Meta:
        model = MetaBusinessUnit
        fields = []

    def enable_api_enrollment(self):
        if not self.instance.api_enrollment_business_units().count():
            self.instance.create_enrollment_business_unit()
        return self.instance


class AddMBUTagForm(forms.Form):
    existing_tag = forms.ModelChoiceField(label="existing tag", queryset=Tag.objects.none(), required=False)
    new_tag_name = forms.CharField(label="new tag name", max_length=200, required=False)
    restrict_new_tag_to_mbu = forms.BooleanField(label="restrict new tag to mbu", required=False)

    def __init__(self, *args, **kwargs):
        self.mbu = kwargs.pop('meta_business_unit')
        super(AddMBUTagForm, self).__init__(*args, **kwargs)
        etqs = Tag.objects.available_for_meta_business_unit(self.mbu)
        self.fields['existing_tag'].queryset = etqs.exclude(metabusinessunittag__meta_business_unit=self.mbu)

    def save(self):
        tag = self.cleaned_data['existing_tag']
        if not tag:
            if self.cleaned_data['restrict_new_tag_to_mbu']:
                tag_mbu = self.mbu
            else:
                tag_mbu = None
            tag, _ = Tag.objects.get_or_create(name=self.cleaned_data['new_tag_name'],
                                               meta_business_unit=tag_mbu)
        return MetaBusinessUnitTag.objects.get_or_create(meta_business_unit=self.mbu,
                                                         tag=tag)


class AddMachineTagForm(forms.Form):
    existing_tag = forms.ChoiceField(label="existing tag", choices=[], required=False)
    new_tag_name = forms.CharField(label="new tag name", max_length=200, required=False)
    new_tag_mbu = forms.ChoiceField(label="new tag mbu", choices=[], required=False)

    def __init__(self, *args, **kwargs):
        self.machine = Machine(kwargs.pop('machine_serial_number'))
        super(AddMachineTagForm, self).__init__(*args, **kwargs)
        self.fields['existing_tag'].choices = [(t.id, str(t)) for t in self.machine.available_tags()]
        self.fields['existing_tag'].choices.insert(0, (None, "-"))
        self.fields['new_tag_mbu'].choices = [(mbu.id, str(mbu)) for mbu in self.machine.meta_business_units()]
        self.fields['new_tag_mbu'].choices.insert(0, (None, "-"))

    def save(self):
        tag_id = self.cleaned_data['existing_tag']
        if not tag_id:
            if self.cleaned_data['new_tag_mbu']:
                tag_mbu = MetaBusinessUnit.objects.get(pk=self.cleaned_data['new_tag_mbu'])
            else:
                tag_mbu = None
            tag, _ = Tag.objects.get_or_create(name=self.cleaned_data['new_tag_name'],
                                               meta_business_unit=tag_mbu)
        else:
            tag = Tag.objects.get(pk=tag_id)
        return MachineTag.objects.get_or_create(serial_number=self.machine.serial_number,
                                                tag=tag)
