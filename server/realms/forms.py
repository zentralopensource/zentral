from django import forms
from django.db.models import Q
from .models import Realm, RealmGroup, RealmGroupMapping, RealmTagMapping, RealmUser


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


class RealmTagMappingForm(forms.ModelForm):
    class Meta:
        model = RealmTagMapping
        fields = "__all__"
        widgets = {"realm": forms.HiddenInput}

    def __init__(self, *args, **kwargs):
        realm = kwargs.pop("realm")
        kwargs.setdefault("initial", {})["realm"] = realm
        super().__init__(*args, **kwargs)
        self.fields["realm"].queryset = self.fields["realm"].queryset.filter(pk=realm.pk)


class RealmGroupSearchForm(forms.Form):
    template_name = "django/forms/search.html"
    display_name = forms.CharField(label="Name", required=False)
    realm = forms.ModelChoiceField(label="Realm", queryset=Realm.objects.all(), required=False)

    def get_queryset(self):
        qs = RealmGroup.objects.select_related("realm").order_by("display_name")
        dn = self.cleaned_data.get("display_name")
        if dn:
            qs = qs.filter(display_name__icontains=dn)
        realm = self.cleaned_data.get("realm")
        if realm:
            qs = qs.filter(realm=realm)
        return qs


class RealmUserSearchForm(forms.Form):
    template_name = "django/forms/search.html"
    q = forms.CharField(label="Name, email", required=False)
    realm = forms.ModelChoiceField(label="Realm", queryset=Realm.objects.all(), required=False)
    realm_group = forms.ModelChoiceField(label="Group", queryset=RealmGroup.objects.all(), required=False)

    def get_queryset(self):
        qs = RealmUser.objects.all().select_related("realm").order_by("username", "email")
        q = self.cleaned_data.get("q")
        if q:
            qs = qs.filter(
                Q(username__icontains=q)
                | Q(email__icontains=q)
                | Q(last_name__icontains=q)
                | Q(first_name__icontains=q)
            )
        realm = self.cleaned_data.get("realm")
        if realm:
            qs = qs.filter(realm=realm)
        # TODO recursive option
        realm_group = self.cleaned_data.get("realm_group")
        if realm_group:
            qs = qs.filter(groups=realm_group)
        return qs
