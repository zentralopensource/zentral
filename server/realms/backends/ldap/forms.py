from django import forms
from django.contrib.auth.forms import UsernameField
import ldap

from realms.forms import RealmForm
from . import get_ldap_connection


class LDAPRealmForm(RealmForm):
    host = forms.CharField(required=True)
    bind_dn = forms.CharField(required=True)
    bind_password = forms.CharField(required=True, widget=forms.PasswordInput(render_value=True))
    users_base_dn = forms.CharField(required=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for attr in ("host", "bind_dn", "bind_password", "users_base_dn"):
            self.fields[attr].initial = self.instance.config.get(attr)

    def clean(self):
        super().clean()
        host = self.cleaned_data.get("host")
        bind_dn = self.cleaned_data.get("bind_dn")
        bind_password = self.cleaned_data.get("bind_password")

        if host and bind_dn and bind_password:
            try:
                conn = get_ldap_connection(host)
            except ldap.LDAPError as e:
                e_dict = e.args[0]
                self.add_error("host", e_dict.get("desc", e_dict.get("info", str(e))))
            except Exception as e:
                self.add_error("host", str(e))
            else:
                try:
                    conn.simple_bind_s(bind_dn, bind_password)
                except ldap.LDAPError as e:
                    e_dict = e.args[0]
                    self.add_error("bind_password", e_dict.get("desc", e_dict.get("info", str(e))))
                except Exception as e:
                    self.add_error("bind_password", str(e))

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
