from django import forms
from zentral.contrib.inventory.models import MetaBusinessUnit
from .models import DistributedQuery


class DistributedQueryForm(forms.ModelForm):
    meta_business_unit = forms.ModelChoiceField(label="Business unit",
                                                queryset=MetaBusinessUnit.objects.available_for_api_enrollment(),
                                                required=False,
                                                widget=forms.Select(attrs={'class': 'form-control'}))

    class Meta:
        model = DistributedQuery
        fields = ['query', 'meta_business_unit', 'shard']
