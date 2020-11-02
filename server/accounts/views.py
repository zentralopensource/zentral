import json
import uuid
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import REDIRECT_FIELD_NAME, login as auth_login
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.core import signing
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, resolve_url
from django.template.response import TemplateResponse
from django.urls import reverse, reverse_lazy
from django.utils.http import is_safe_url
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import DetailView, FormView, ListView, TemplateView, View
from u2flib_server.u2f import begin_registration, complete_registration
from zentral.conf import settings as zentral_settings
from zentral.utils.http import user_agent_and_ip_address_from_request
from realms.models import Realm
from .events import post_failed_verification_event, post_verification_device_event
from .forms import (ZentralAuthenticationForm,
                    AddTOTPForm, AddUserForm, CheckPasswordForm, RegisterU2FDeviceForm, UpdateUserForm,
                    VerifyTOTPForm, VerifyU2FForm)
from .models import User, UserTOTP, UserU2F


@sensitive_post_parameters()
@csrf_protect
@never_cache
def login(request):
    """
    Displays the login form and handles the login action.
    """
    redirect_to = request.POST.get(REDIRECT_FIELD_NAME,
                                   request.GET.get(REDIRECT_FIELD_NAME, ''))

    form = realm = None

    if request.method == "POST":
        form = ZentralAuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()

            # Ensure the user-originating redirection url is safe.
            if not is_safe_url(url=redirect_to,
                               allowed_hosts={request.get_host()},
                               require_https=request.is_secure()):
                redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)

            if user.has_verification_device:
                # Redirect to verification page
                token = signing.dumps({"auth_backend": user.backend,
                                       "redirect_to": redirect_to,
                                       "user_id": user.id},
                                      salt="zentral_verify_token",
                                      key=settings.SECRET_KEY)
                request.session["verification_token"] = token
                user_agent, _ = user_agent_and_ip_address_from_request(request)
                try:
                    verification_device = user.get_prioritized_verification_devices(user_agent)[0]
                except ValueError:
                    form.add_error(None, "No configured verification devices compatible with your current browser.")
                else:
                    return HttpResponseRedirect(verification_device.get_verification_url())
            else:
                # Okay, security check complete. Log the user in.
                auth_login(request, form.get_user())

                return HttpResponseRedirect(redirect_to)
    else:
        try:
            realm_pk = uuid.UUID(request.GET.get("realm"))
            realm = Realm.objects.get(enabled_for_login=True, pk=realm_pk)
        except (Realm.DoesNotExist, TypeError, ValueError):
            form = ZentralAuthenticationForm(request)

    context = {
        "redirect_to": redirect_to,
        "redirect_field_name": REDIRECT_FIELD_NAME,
    }
    if form:
        context["form"] = form
    if realm:
        login_realms = [realm]
    else:
        login_realms = Realm.objects.filter(enabled_for_login=True)
    context["login_realms"] = [(r, reverse("realms:login", args=(r.pk,)))
                               for r in login_realms]

    return TemplateResponse(request, "registration/login.html", context)


class VerificationMixin(object):
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        request = self.request
        user_agent, _ = user_agent_and_ip_address_from_request(request)
        kwargs["session"] = request.session
        kwargs["user_agent"] = user_agent
        return kwargs

    def form_valid(self, form):
        auth_login(self.request, form.user)  # form.user has the backend (carried by the token from the login view)
        return HttpResponseRedirect(form.redirect_to)

    def form_invalid(self, form):
        post_failed_verification_event(self.request, form.user)
        return super().form_invalid(form)


class VerifyTOTPView(VerificationMixin, FormView):
    template_name = "accounts/verify_totp.html"
    form_class = VerifyTOTPForm


class VerifyU2FView(VerificationMixin, FormView):
    template_name = "accounts/verify_u2f.html"
    form_class = VerifyU2FForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data()
        ctx["u2f_challenge_json"] = VerifyU2FForm(session=self.request.session).set_u2f_challenge()
        if "u2f_challenge" in self.request.session:
            ctx["u2f_challenge_json"] = json.dumps(self.request.session["u2f_challenge"])
        return ctx


class CanManageUsersMixin(PermissionRequiredMixin):
    permission_required = ('accounts.add_user', 'accounts.change_user', 'accounts.delete_user')


class UsersView(CanManageUsersMixin, ListView):
    model = User


class NginxAuthRequestView(View):
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            if request.is_ajax() or request.META.get('HTTP_ACCEPT', '').startswith('application/json'):
                status_code = 403
            else:
                status_code = 401
            response = HttpResponse('Signed out')
            response.status_code = status_code
            return response
        else:
            return HttpResponse("OK")


class AddUserView(CanManageUsersMixin, FormView):
    template_name = "accounts/user_form.html"
    form_class = AddUserForm
    success_url = reverse_lazy("users:list")

    def form_valid(self, form):
        form.save(self.request)
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "Send an email invitation"
        return ctx


class UpdateUserView(CanManageUsersMixin, FormView):
    template_name = "accounts/user_form.html"
    form_class = UpdateUserForm
    success_url = reverse_lazy("users:list")

    def dispatch(self, request, *args, **kwargs):
        self.user = get_object_or_404(User, pk=kwargs["pk"])
        if not self.user.editable():
            return HttpResponseRedirect(self.success_url)
        return super().dispatch(request, *args, **kwargs)

    def get_initial(self):
        return {"username": self.user.username,
                "email": self.user.email,
                "is_superuser": self.user.is_superuser}

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["instance"] = self.user
        return kwargs

    def form_valid(self, form):
        form.save(self.request)
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["managed_user"] = self.user
        ctx["title"] = "Update user {}".format(self.user)
        return ctx


class DeleteUserView(CanManageUsersMixin, TemplateView):
    template_name = "accounts/delete_user.html"

    def dispatch(self, request, *args, **kwargs):
        self.user = get_object_or_404(User, pk=kwargs["pk"])
        if not self.user.deletable():
            return HttpResponseRedirect(reverse("users:list"))
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["managed_user"] = self.user
        return ctx

    def post(self, request, *args, **kwargs):
        msg = "User {} deleted".format(self.user)
        self.user.delete()
        messages.info(request, msg)
        return HttpResponseRedirect(reverse("users:list"))


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
    success_url = reverse_lazy("users:verification_devices")

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form):
        user_totp = form.save()
        post_verification_device_event(self.request, self.request.user,
                                       "added", user_totp)
        return super().form_valid(form)

    def form_invalid(self, form):
        post_verification_device_event(self.request, self.request.user,
                                       "not_added")
        return super().form_invalid(form)


class DeleteVerificationDeviceView(LoginRequiredMixin, FormView):
    template_name = "accounts/delete_verification_device.html"
    form_class = CheckPasswordForm
    success_url = reverse_lazy("users:verification_devices")

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
        self.device.delete()
        post_verification_device_event(self.request, self.request.user,
                                       "removed", self.device)
        return super().form_valid(form)

    def form_invalid(self, form):
        post_verification_device_event(self.request, self.request.user,
                                       "not_removed", self.device)
        return super().form_invalid(form)


class DeleteTOTPView(DeleteVerificationDeviceView):
    model = UserTOTP


class RegisterU2FDeviceView(LoginRequiredMixin, FormView):
    template_name = "accounts/register_u2f_device.html"
    form_class = RegisterU2FDeviceForm
    success_url = reverse_lazy("users:verification_devices")

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
        UserU2F.objects.create(user=self.request.user,
                               name=form.cleaned_data["name"],
                               device=device)
        messages.info(self.request, "U2F device registered")
        return super().form_valid(form)


class DeleteU2FDeviceView(DeleteVerificationDeviceView):
    model = UserU2F
