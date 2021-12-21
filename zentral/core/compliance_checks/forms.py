from django import forms
from .models import ComplianceCheck
from . import compliance_check_class_from_model


class ComplianceCheckForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        self.model = kwargs.pop("model")
        super().__init__(*args, **kwargs)

    class Meta:
        model = ComplianceCheck
        fields = ("name", "description")
        widgets = {
            "name": forms.TextInput(attrs={"autofocus": "true"})
        }

    def clean_name(self):
        name = self.cleaned_data.get("name")
        if name:
            qs = ComplianceCheck.objects.filter(model=self.model, name=name)
            if self.instance.pk:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.count():
                cc_cls = compliance_check_class_from_model(self.model)
                raise forms.ValidationError(f"{cc_cls.model_display} with this name already exists")
        return name
