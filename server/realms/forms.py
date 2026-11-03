from django import forms
from django.db import transaction
from django.db.models import Q
from .models import Realm, RealmGroup, RealmGroupMapping, RealmUser, RealmUserGroupMembership, RoleMapping


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


class AddRealmUserToGroupForm(forms.Form):
    realm_group = forms.ModelChoiceField(label="Realm Group", queryset=RealmGroup.objects.for_update(), required=True)

    def __init__(self, *args, **kwargs):
        self.realm_user = kwargs.pop("realm_user")
        super().__init__(*args, **kwargs)
        self.fields["realm_group"].queryset = self.fields["realm_group"].queryset.filter(
          realm=self.realm_user.realm
        ).exclude(
          pk__in=[g.pk for g in self.realm_user.groups.all()]
        ).order_by("display_name")

    def save(self):
        """The new membership, or None if the realm user is already a member of the group."""
        realm_group = self.cleaned_data["realm_group"]
        with transaction.atomic():
            # no unique constraint on the memberships: two console requests for the same user wait on this lock.
            # The SCIM member writes do not take it.
            RealmUser.objects.select_for_update().get(pk=self.realm_user.pk)
            if RealmUserGroupMembership.objects.filter(user=self.realm_user, group=realm_group).exists():
                return None
            return RealmUserGroupMembership.objects.create(user=self.realm_user, group=realm_group)


class RealmGroupMappingForm(forms.ModelForm):
    class Meta:
        model = RealmGroupMapping
        fields = "__all__"


class RoleMappingForm(forms.ModelForm):
    class Meta:
        model = RoleMapping
        fields = ("realm_group", "group")
