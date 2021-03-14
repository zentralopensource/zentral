import json
import logging
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy
from django.views.generic import DetailView, FormView, TemplateView
from u2flib_server.u2f import begin_registration, complete_registration
from accounts.events import post_verification_device_event
from accounts.forms import AddTOTPForm, CheckPasswordForm, RegisterU2FDeviceForm
from accounts.models import UserTOTP, UserU2F
from zentral.conf import settings as zentral_settings


logger = logging.getLogger("zentral.accounts.views.user")


class ProfileView(LoginRequiredMixin, TemplateView):
    template_name = "accounts/profile.html"


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

    def dispatch(self, request, *args, **kwargs):
        self.device = get_object_or_404(self.model, user=request.user, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["object"] = self.device
        return ctx

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form):
        post_verification_device_event(self.request, self.request.user, "delete", self.device)
        self.device.delete()
        return super().form_valid(form)


class DeleteTOTPView(DeleteVerificationDeviceView):
    model = UserTOTP


class RegisterU2FDeviceView(LoginRequiredMixin, FormView):
    template_name = "accounts/register_u2f_device.html"
    form_class = RegisterU2FDeviceForm
    success_url = reverse_lazy("accounts:verification_devices")

    def get(self, request, *args, **kwargs):
        user_devices = [ud.device for ud in request.user.useru2f_set.all()]
        register_request = begin_registration(zentral_settings["api"]["tls_hostname"], user_devices)
        self.request.session["u2f_challenge"] = dict(register_request)
        return super().get(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data()
        ctx["u2f_challenge_json"] = json.dumps(self.request.session["u2f_challenge"])
        return ctx

    def form_valid(self, form):
        token_response = form.cleaned_data["token_response"]
        u2f_challenge = self.request.session["u2f_challenge"]
        device, _ = complete_registration(u2f_challenge, token_response,
                                          [zentral_settings["api"]["tls_hostname"]])
        user_u2f = UserU2F.objects.create(user=self.request.user,
                                          name=form.cleaned_data["name"],
                                          device=device)
        post_verification_device_event(self.request, self.request.user, "create", user_u2f)
        messages.info(self.request, "U2F device registered")
        return super().form_valid(form)


class DeleteU2FDeviceView(DeleteVerificationDeviceView):
    model = UserU2F
