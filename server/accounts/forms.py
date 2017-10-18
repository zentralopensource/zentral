from urllib.parse import urlparse
from django import forms
from django.conf import settings as django_settings
from django.contrib.auth.forms import AuthenticationForm, PasswordResetForm, UsernameField
from django.core import signing
from django.utils.crypto import get_random_string
from django.utils.translation import ugettext_lazy as _
import pyotp
from u2flib_server.u2f import begin_authentication, complete_authentication
from .models import User, UserTOTP, UserU2F
from zentral.conf import settings as zentral_settings


class ZentralAuthenticationForm(AuthenticationForm):
    username = UsernameField(
        max_length=254,
        widget=forms.TextInput(attrs={'autofocus': '',
                                      'autocorrect': 'off',
                                      'autocapitalize': 'none'}),
    )


class AddUserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("username", "email")
        field_classes = {'username': UsernameField}

    def save(self, request):
        user = super(AddUserForm, self).save(commit=False)
        user.set_password(get_random_string(1024))
        user.save()
        prf = PasswordResetForm({"email": user.email})
        if prf.is_valid():
            prf.save(request=request, use_https=True,
                     email_template_name='registration/invitation_email.html',
                     subject_template_name='registration/invitation_subject.txt')
        return user


class UpdateUserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("username", "email", "is_superuser")
        field_classes = {'username': UsernameField}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.instance.username_and_email_editable():
            self.fields["username"].disabled = True
            self.fields["email"].disabled = True
        if not self.instance.is_superuser_editable():
            self.fields["is_superuser"].disabled = True


class AddTOTPForm(forms.Form):
    secret = forms.CharField(widget=forms.HiddenInput)
    verification_code = forms.CharField(widget=forms.TextInput(attrs={"size": 6, "maxlength": 6}))
    name = forms.CharField(widget=forms.TextInput(attrs={'autofocus': ''}))

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)
        self.initial_secret = pyotp.random_base32()
        self.fields["secret"].initial = self.initial_secret

    def get_provisioning_uri(self):
        label = urlparse(zentral_settings["api"]["tls_hostname"]).netloc
        return (pyotp.totp.TOTP(self.initial_secret)
                          .provisioning_uri(self.user.email, label))

    def clean_name(self):
        name = self.cleaned_data["name"]
        if name and UserTOTP.objects.filter(user=self.user, name=name).count() > 0:
            self.add_error("name", "A verification device with this name already exists for this user")
        return name

    def clean(self):
        if self.user.is_remote:
            raise forms.ValidationError("Cannot add a verification device to a remote user")
        secret = self.cleaned_data["secret"]
        verification_code = self.cleaned_data["verification_code"]
        totp = pyotp.totp.TOTP(secret)
        if not totp.verify(verification_code):
            self.add_error("verification_code", "Wrong verification code")
        return self.cleaned_data

    def save(self):
        return UserTOTP.objects.create(user=self.user,
                                       secret=self.cleaned_data["secret"],
                                       name=self.cleaned_data["name"])


class BaseVerifyForm(forms.Form):
    def __init__(self, *args, **kwargs):
        self.session = kwargs.pop("session")
        self.user_agent = kwargs.pop("user_agent", None)
        token_data = signing.loads(self.session["verification_token"],
                                   salt="zentral_verify_token",
                                   key=django_settings.SECRET_KEY)
        self.redirect_to = token_data["redirect_to"]
        self.user = User.objects.get(pk=token_data["user_id"])
        self.user.backend = token_data["auth_backend"]  # used by contrib.auth.login
        super().__init__(*args, **kwargs)

    def get_alternative_verification_links(self):
        return set((vd.get_verification_url(), "Use a {} device".format(vd.TYPE))
                   for vd in self.user.get_prioritized_verification_devices(self.user_agent)
                   if vd.TYPE != self.device_type)


class VerifyTOTPForm(BaseVerifyForm):
    device_type = UserTOTP.TYPE
    verification_code = forms.CharField(max_length=6,
                                        widget=forms.TextInput(attrs={'autofocus': ''}))

    def clean(self):
        cleaned_data = super().clean()
        verification_code = cleaned_data["verification_code"]
        for verification_device in self.user.usertotp_set.all():
            if verification_device.verify(verification_code):
                break
        else:
            self.add_error("verification_code", _("Invalid code"))
        return cleaned_data


class VerifyU2FForm(BaseVerifyForm):
    device_type = UserU2F.TYPE
    token_response = forms.CharField(required=True)

    def set_u2f_challenge(self):
        user_devices = [ud.device for ud in self.user.useru2f_set.all()]
        if user_devices:
            authentication_request = begin_authentication(zentral_settings["api"]["tls_hostname"], user_devices)
            u2f_challenge = self.session["u2f_challenge"] = dict(authentication_request)
            return u2f_challenge

    def clean(self):
        cleaned_data = super().clean()
        u2f_challenge = self.session["u2f_challenge"]
        token_response = cleaned_data["token_response"]
        device, _, _ = complete_authentication(u2f_challenge, token_response,
                                               [zentral_settings["api"]["tls_hostname"]])
        if not device:
            raise forms.ValidationError("Could not complete the U2F authentication")
        return cleaned_data


class CheckPasswordForm(forms.Form):
    password = forms.CharField(label=_("Password"),
                               widget=forms.PasswordInput(attrs={'autofocus': ''}))

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data["password"]
        if password and not self.user.check_password(password):
            self.add_error("password", _("Your password was entered incorrectly"))
        return cleaned_data


class RegisterU2FDeviceForm(forms.Form):
    token_response = forms.CharField(required=True,
                                     widget=forms.HiddenInput)
    name = forms.CharField(max_length=256, required=True,
                           widget=forms.TextInput(attrs={'autofocus': ''}),
                           help_text="Enter a name and touch your U2F device.")

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)

    def clean_name(self):
        name = self.cleaned_data.get("name")
        if name and UserU2F.objects.filter(user=self.user, name=name).count():
            raise forms.ValidationError("A U2F device with this name is already registered with your account")
        return name
