from django import forms
from django.utils.crypto import get_random_string
from .models import BusinessUnit, Source


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


class BusinessUnitSearchForm(forms.Form):
    name = forms.CharField(label="name", max_length=64, required=False)
    source = forms.ModelChoiceField(queryset=Source.objects.current_business_unit_sources(),
                                    required=False,
                                    widget=forms.Select(attrs={'class': 'form-control'}))


class BusinessUnitForm(forms.ModelForm):
    class Meta:
        fields = ('name',)
        model = BusinessUnit

    def save(self):
        name = self.cleaned_data['name']
        if self.instance.reference:
            self.instance.name = name
            self.instance.mt_hash = self.instance.hash()
            self.instance.save()
        else:
            tree = {'source': {'module': 'zentral.contrib.inventory',
                               'name': 'Inventory'},
                    'reference': get_random_string(64),
                    'name': name}
            self.instance, _ = BusinessUnit.objects.commit(tree)
        return self.instance
