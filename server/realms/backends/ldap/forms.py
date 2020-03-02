from django import forms
from django.contrib.auth.forms import UsernameField

from realms.forms import RealmForm


class LDAPRealmForm(RealmForm):
    host = forms.CharField(required=True)
    bind_dn = forms.CharField(required=True)
    bind_password = forms.CharField(required=True, widget=forms.PasswordInput)
    users_base_dn = forms.CharField(required=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance:
            for attr in ("host", "bind_dn", "bind_password", "users_base_dn"):
                self.fields[attr].initial = self.instance.config.get(attr)

    def get_config(self):
        return {attr: self.cleaned_data.get(attr)
                for attr in ("host", "bind_dn", "bind_password", "users_base_dn")}


class LoginForm(forms.Form):
    username = UsernameField(widget=forms.TextInput(attrs={'autofocus': True}))
    password = forms.CharField(strip=False, widget=forms.PasswordInput)

    def __init__(self, *args, **kwargs):
        self.backend_instance = kwargs.pop("backend_instance")
        super().__init__(*args, **kwargs)

    def clean(self):
        username = self.cleaned_data.get("username")
        password = self.cleaned_data.get("password")
        if not self.backend_instance.authenticate(username, password):
            self.add_error("password", forms.ValidationError("Please enter a correct username and password"))
