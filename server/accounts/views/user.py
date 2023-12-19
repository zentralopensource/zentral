from base64 import urlsafe_b64encode
import json
import logging
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy
from django.views.generic import DetailView, FormView, TemplateView
from webauthn import generate_registration_options, options_to_json, verify_registration_response
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, RegistrationCredential
from accounts.events import post_verification_device_event
from accounts.forms import AddTOTPForm, CheckPasswordForm, RegisterWebAuthnDeviceForm, UpdateProfileForm
from accounts.models import UserTOTP, UserWebAuthn
from zentral.conf import settings as zentral_settings
from zentral.utils.base64 import trimmed_urlsafe_b64decode


logger = logging.getLogger("zentral.accounts.views.user")


class ProfileView(LoginRequiredMixin, TemplateView):
    template_name = "accounts/profile.html"


class UpdateProfileView(LoginRequiredMixin, FormView):
    template_name = "accounts/profile_form.html"
    form_class = UpdateProfileForm
    success_url = reverse_lazy("accounts:profile")

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)


class UserVerificationDevicesView(LoginRequiredMixin, DetailView):
    template_name = "accounts/user_verification_devices.html"
    context_object_name = "object"  # to not overwrite the logged in user

    def get_object(self):
        return self.request.user

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["verification_devices"] = self.request.user.get_verification_devices()
        return ctx


class AddTOTPView(LoginRequiredMixin, FormView):
    template_name = "accounts/add_totp.html"
    form_class = AddTOTPForm
    success_url = reverse_lazy("accounts:verification_devices")

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form):
        user_totp = form.save()
        post_verification_device_event(self.request, self.request.user, "create", user_totp)
        return super().form_valid(form)


class DeleteVerificationDeviceView(LoginRequiredMixin, FormView):
    template_name = "accounts/delete_verification_device.html"
    form_class = CheckPasswordForm
    success_url = reverse_lazy("accounts:verification_devices")

    def get_device(self):
        self.device = get_object_or_404(self.model, user=self.request.user, pk=self.kwargs["pk"])

    def get_context_data(self, **kwargs):
        self.get_device()
        ctx = super().get_context_data(**kwargs)
        ctx["object"] = self.device
        return ctx

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form):
        self.get_device()
        post_verification_device_event(self.request, self.request.user, "delete", self.device)
        self.device.delete()
        return super().form_valid(form)


class DeleteTOTPView(DeleteVerificationDeviceView):
    model = UserTOTP


class RegisterWebAuthnDeviceView(LoginRequiredMixin, FormView):
    template_name = "accounts/register_webauthn_device.html"
    form_class = RegisterWebAuthnDeviceForm
    success_url = reverse_lazy("accounts:verification_devices")

    def get(self, request, *args, **kwargs):
        credentials = []
        for user_device in request.user.userwebauthn_set.all():
            credentials.append(PublicKeyCredentialDescriptor(id=user_device.get_key_handle_bytes()))
        registration_options = json.loads(
            options_to_json(
                generate_registration_options(
                    rp_id=zentral_settings["api"]["fqdn"],
                    rp_name="Zentral",
                    exclude_credentials=credentials,
                    user_id=str(request.user.pk),
                    user_name=request.user.username,
                )
            )
        )
        request.session["webauthn_challenge"] = registration_options
        return super().get(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data()
        ctx["webauthn_challenge"] = self.request.session["webauthn_challenge"]
        return ctx

    def form_valid(self, form):
        webauthn_challenge = self.request.session["webauthn_challenge"]
        try:
            credential = RegistrationCredential.parse_raw(form.cleaned_data["token_response"])
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=trimmed_urlsafe_b64decode(webauthn_challenge["challenge"]),
                expected_origin=zentral_settings["api"]["tls_hostname"],
                expected_rp_id=zentral_settings["api"]["fqdn"],
                require_user_verification=False
            )
        except Exception:
            logger.exception("Could not verify registration")
            messages.error(self.request, "Authentication error")
            return self.form_invalid(form)
        transports = json.loads(form.cleaned_data["token_response"]).get("transports", [])
        user_device = UserWebAuthn.objects.create(
            user=self.request.user,
            name=form.cleaned_data["name"],
            key_handle=urlsafe_b64encode(verification.credential_id).decode("ascii").rstrip("="),
            public_key=verification.credential_public_key,
            rp_id=zentral_settings["api"]["fqdn"],
            transports=transports,
            sign_count=verification.sign_count
        )
        post_verification_device_event(self.request, self.request.user, "create", user_device)
        messages.info(self.request, "Security key registered")
        return super().form_valid(form)


class DeleteWebAuthnDeviceView(DeleteVerificationDeviceView):
    model = UserWebAuthn
