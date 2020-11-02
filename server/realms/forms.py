from django import forms
from .models import Realm


class RealmForm(forms.ModelForm):
    # max 15 days
    login_session_expiry = forms.IntegerField(
        required=False, min_value=0, max_value=1296000, initial=0,
        help_text="Session expiry in seconds. If value is 0, the user’s session"
                  " cookie will expire when the user’s Web browser is closed."
    )

    class Meta:
        model = Realm
        fields = '__all__'

    def get_config(self):
        # to be implemented in the sub classes
        return {}

    def clean(self):
        super().clean()
        if self.cleaned_data.get("login_session_expiry") in (None, ""):
            if self.cleaned_data.get("enabled_for_login"):
                self.add_error("login_session_expiry", "You need to pick a value between 0 and 1296000 seconds")

    def save(self, *args, **kwargs):
        commit = kwargs.pop("commit", True)
        kwargs["commit"] = False
        realm = super().save(*args, **kwargs)
        realm.config = self.get_config()
        if commit:
            realm.save()
        return realm
