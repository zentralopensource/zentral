from django import forms


class MachineSearchForm(forms.Form):
    serial_number = forms.CharField(label="serial number", max_length=32, required=False)
    name = forms.CharField(label="name", max_length=64, required=False) 


class MachineGroupSearchForm(forms.Form):
    name = forms.CharField(label="name", max_length=64, required=True)


class BusinessUnitSearchForm(forms.Form):
    name = forms.CharField(label="name", max_length=64, required=True)
