import json
import logging
from urllib.parse import urlparse
from django import forms
from django.conf import settings as django_settings
from django.contrib.auth.forms import AuthenticationForm, PasswordResetForm as DjangoPasswordResetForm,  UsernameField
from django.contrib.auth.models import Group
from django.core import signing, validators
from django.db.models import Q
from django.utils.crypto import get_random_string
from django.utils.translation import gettext_lazy as _
import pyotp
from webauthn import generate_authentication_options, options_to_json, verify_authentication_response
from webauthn.helpers import parse_authentication_credential_json
from webauthn.helpers.structs import PublicKeyCredentialDescriptor
from zentral.conf import settings as zentral_settings
from zentral.conf.config import ConfigList
from zentral.utils.base64 import trimmed_urlsafe_b64decode
from .models import User, UserTOTP, UserWebAuthn
from .password_reset import handler as password_reset_handler
from .utils import all_permissions_queryset


logger = logging.getLogger("zentral.accounts.forms")


class ZentralAuthenticationForm(AuthenticationForm):
    username = UsernameField(
        max_length=254,
        widget=forms.TextInput(attrs={'autofocus': True,
                                      'autocorrect': 'off',
                                      'autocapitalize': 'none'}),
    )


class GroupForm(forms.ModelForm):
    class Meta:
        model = Group
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["permissions"].queryset = all_permissions_queryset()


class InviteUserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("username", "email")
        field_classes = {'username': UsernameField}
        widgets = {'username': forms.TextInput({"autofocus": True})}

    def clean_email(self):
        email = self.cleaned_data.get("email")
        if not email:
            return email
        try:
            allowed_domains = zentral_settings["users"]["allowed_invitation_domains"]
        except KeyError:
            # not configured, nothing to check
            return email
        if not isinstance(allowed_domains, ConfigList) or any(not isinstance(d, str) for d in allowed_domains):
            raise forms.ValidationError("Configuration error: "
                                        "users.allowed_invitation_domains is not a list of strings")
        try:
            domain = email.split("@")[1]
        except IndexError:
            # should never happen
            raise forms.ValidationError("Could not extract domain.")
        if domain not in allowed_domains:
            raise forms.ValidationError("Email domain not allowed.")
        return email

    def save(self):
        user = super(InviteUserForm, self).save(commit=False)
        user.set_password(get_random_string(1024))
        user.save()
        password_reset_handler.send_password_reset(user, invitation=True)
        return user


class ServiceAccountNameValidator(validators.RegexValidator):
    regex = r'^[\w.+-]+$'
    message = _(
        'Enter a valid name. This value may contain only letters, '
        'digits, and ./+/-/_ characters.'
    )
    flags = 0


class ServiceAccountForm(forms.ModelForm):
    name_validator = ServiceAccountNameValidator()
    username = forms.CharField(
        label="Name",
        max_length=150,
        required=True,
        help_text="Required. 150 characters or fewer. Letters, digits and ./+/-/_ only.",
        validators=[name_validator],
        widget=forms.TextInput({"autofocus": True})
    )

    class Meta:
        model = User
        fields = ("username", "description", "groups")

    def clean(self):
        username = self.cleaned_data.get("username")
        if username:
            email = "{}@{}".format(username, zentral_settings["api"]["fqdn"])
            user_qs = User.objects.filter(Q(username=username) | Q(email=email))
            if self.instance.pk:
                user_qs = user_qs.exclude(pk=self.instance.pk)
            if user_qs.count():
                if user_qs.filter(is_service_account=True).count():
                    self.add_error("username", "A service account with this name already exists.")
                elif user_qs.filter(is_service_account=False).count():
                    self.add_error("username", "A user with this name already exists.")
            self.instance.email = email
        self.instance.is_service_account = True


class UpdateUserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("username", "email", "is_superuser", "groups", "items_per_page")
        field_classes = {'username': UsernameField}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.instance.username_and_email_editable():
            del self.fields["username"]
            del self.fields["email"]
        if not self.instance.is_superuser_editable():
            del self.fields["is_superuser"]
        if self.instance.is_remote:
            del self.fields["groups"]


class UpdateProfileForm(forms.Form):
    items_per_page = forms.IntegerField(
        min_value=1, max_value=500,
        help_text="Number of items per page in lists"
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)
        self.fields["items_per_page"].initial = self.user.items_per_page

    def save(self, *args, **kwargs):
        self.user.items_per_page = self.cleaned_data["items_per_page"]
        self.user.save()
        return self.user


class AddTOTPForm(forms.Form):
    secret = forms.CharField(widget=forms.HiddenInput)
    name = forms.CharField(widget=forms.TextInput(attrs={'autofocus': ''}))
    verification_code = forms.CharField(widget=forms.TextInput(attrs={"size": 6, "maxlength": 6}))

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)
        if self.is_bound:
            # verification code error
            self.fields["name"].widget.attrs.pop("autofocus")
            self.fields["verification_code"].widget.attrs["autofocus"] = ""
        else:
            # new totp
            self.fields["secret"].initial = pyotp.random_base32()

    @property
    def initial_secret(self):
        if self.is_bound:
            return self.data["secret"]
        else:
            return self.fields["secret"].initial

    def get_provisioning_uri(self):
        label = urlparse(zentral_settings["api"]["tls_hostname"]).netloc
        return pyotp.totp.TOTP(self.initial_secret).provisioning_uri(self.user.email, label)

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
        links = set([])
        for vd in self.user.get_prioritized_verification_devices(self.user_agent):
            if vd.TYPE == self.device_type:
                continue
            url = vd.get_verification_url()
            if vd.TYPE == UserTOTP.TYPE:
                anchor_text = "Enter two-factor authentication code"
            elif vd.TYPE == UserWebAuthn.TYPE:
                anchor_text = "Use a security key"
            else:
                anchor_text = f"Use a {vd.TYPE} device"
            links.add((url, anchor_text))
        return links


class VerifyTOTPForm(BaseVerifyForm):
    device_type = UserTOTP.TYPE
    verification_code = forms.CharField(max_length=6,
                                        widget=forms.TextInput(attrs={'autofocus': ''}))

    def clean(self):
        cleaned_data = super().clean()
        try:
            verification_code = cleaned_data["verification_code"]
        except KeyError:
            pass
        else:
            for verification_device in self.user.usertotp_set.all():
                if verification_device.verify(verification_code):
                    break
            else:
                self.add_error("verification_code", _("Invalid code"))
        return cleaned_data


class VerifyWebAuthnForm(BaseVerifyForm):
    device_type = UserWebAuthn.TYPE
    token_response = forms.CharField(required=True)

    def set_challenge(self):
        credentials = []
        appid = None
        for user_device in self.user.userwebauthn_set.all():
            credentials.append(PublicKeyCredentialDescriptor(id=user_device.get_key_handle_bytes()))
            device_appid = user_device.get_appid()
            if device_appid:
                appid = device_appid
        if credentials:
            authentication_options = json.loads(
                options_to_json(
                    generate_authentication_options(
                        rp_id=zentral_settings["api"]["fqdn"],
                        allow_credentials=credentials,
                    )
                )
            )
            if appid:
                authentication_options["extensions"] = {"appid": appid}
            challenge = self.session["webauthn_challenge"] = dict(authentication_options)
            return challenge

    def clean(self):
        cleaned_data = super().clean()
        webauthn_challenge = self.session["webauthn_challenge"]
        try:
            credential = parse_authentication_credential_json(cleaned_data["token_response"])
        except Exception:
            msg = "Invalid token response"
            logger.exception(msg)
            raise forms.ValidationError(msg)
        try:
            device = self.user.userwebauthn_set.select_for_update().get(key_handle=credential.id)
        except UserWebAuthn.DoesNotExist:
            logger.error(f"Could not find WebAuthn device {credential.id} for user {self.user.pk}")
            raise forms.ValidationError("Unknown security key")
        appid = device.get_appid()
        if appid:
            # legacy U2F registration
            expected_rp_id = appid
        else:
            expected_rp_id = webauthn_challenge["rpId"]
        try:
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=trimmed_urlsafe_b64decode(webauthn_challenge["challenge"]),
                expected_rp_id=expected_rp_id,
                expected_origin=zentral_settings["api"]["tls_hostname"],
                credential_public_key=device.public_key.tobytes(),
                credential_current_sign_count=device.sign_count,
                require_user_verification=False,
            )
        except Exception:
            msg = "Authentication error"
            logger.exception(msg)
            raise forms.ValidationError(msg)
        device.sign_count = verification.new_sign_count
        device.save()
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


class RegisterWebAuthnDeviceForm(forms.Form):
    token_response = forms.CharField(required=True,
                                     widget=forms.HiddenInput)
    name = forms.CharField(max_length=256, required=True,
                           widget=forms.TextInput(attrs={'autofocus': ''}))

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)

    def clean_name(self):
        name = self.cleaned_data.get("name")
        if name and UserWebAuthn.objects.filter(user=self.user, name=name).count():
            raise forms.ValidationError("A security key with this name is already registered with your account")
        return name


class PasswordResetForm(DjangoPasswordResetForm):
    def save(self, *args, **kwargs):
        email = self.cleaned_data["email"]
        for user in self.get_users(email):
            password_reset_handler.send_password_reset(user, invitation=False)
