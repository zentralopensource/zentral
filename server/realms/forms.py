from django import forms
from .models import Realm, RealmGroupMapping


class RealmForm(forms.ModelForm):
    class Meta:
        model = Realm
        fields = '__all__'

    def get_config(self):
        # to be implemented in the sub classes
        return {}

    def save(self, *args, **kwargs):
        commit = kwargs.pop("commit", True)
        kwargs["commit"] = False
        realm = super().save(*args, **kwargs)
        realm.config = self.get_config()
        if commit:
            realm.save()
        return realm


class RealmGroupMappingForm(forms.ModelForm):
    class Meta:
        model = RealmGroupMapping
        fields = "__all__"
        widgets = {"realm": forms.HiddenInput}

    def __init__(self, *args, **kwargs):
        realm = kwargs.pop("realm")
        kwargs.setdefault("initial", {})["realm"] = realm
        super().__init__(*args, **kwargs)
        self.fields["realm"].queryset = self.fields["realm"].queryset.filter(pk=realm.pk)
