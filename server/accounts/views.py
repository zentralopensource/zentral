from datetime import datetime, timedelta
import json
import uuid
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import REDIRECT_FIELD_NAME, login as auth_login
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.core import signing
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, resolve_url
from django.template.response import TemplateResponse
from django.urls import reverse, reverse_lazy
from django.utils.http import is_safe_url
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import DetailView, FormView, TemplateView, View
from rest_framework.authtoken.models import Token
from u2flib_server.u2f import begin_registration, complete_registration
from zentral.conf import settings as zentral_settings
from zentral.utils.http import user_agent_and_ip_address_from_request
from realms.models import Realm
from .events import post_failed_verification_event, post_verification_device_event
from .forms import (AddTOTPForm, CheckPasswordForm,
                    InviteUserForm, RegisterU2FDeviceForm, ServiceAccountForm, UpdateUserForm,
                    VerifyTOTPForm, VerifyU2FForm, ZentralAuthenticationForm)
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


class UsersView(CanManageUsersMixin, TemplateView):
    template_name = "accounts/user_list.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["users"] = User.objects.filter(is_service_account=False)
        ctx["user_count"] = ctx["users"].count()
        ctx["service_accounts"] = User.objects.filter(is_service_account=True)
        ctx["service_account_count"] = ctx["service_accounts"].count()
        return ctx


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
            response = HttpResponse("OK")
            response["X-Zentral-Username"] = request.user.username
            response["X-Zentral-Email"] = request.user.email
            return response


class InviteUserView(CanManageUsersMixin, FormView):
    template_name = "accounts/user_form.html"
    form_class = InviteUserForm
    success_url = reverse_lazy("users:list")

    def form_valid(self, form):
        form.save(self.request)
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "Send an email invitation"
        return ctx


class CreateServiceAccountView(CanManageUsersMixin, FormView):
    template_name = "accounts/service_account_form.html"
    form_class = ServiceAccountForm
    success_url = reverse_lazy("users:list")

    def form_valid(self, form):
        user = form.save(self.request)
        return redirect("users:user_api_token", user.pk)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "Create service account"
        return ctx


class UserView(CanManageUsersMixin, DetailView):
    template_name = "accounts/user_detail.html"
    model = User

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        user = ctx["user"]
        ctx["title"] = "{} {}".format(user.get_type_display().title(), user)
        return ctx


class CreateUserAPITokenView(CanManageUsersMixin, View):
    def post(self, request, *args, **kwargs):
        user = get_object_or_404(User.objects.filter(is_remote=False), pk=kwargs["pk"])
        _, created = Token.objects.get_or_create(user=user)
        if not created:
            messages.warning(request, "User already has an API token")
            return redirect("users:list")
        else:
            return redirect("users:user_api_token", user.pk)


class UserAPITokenView(CanManageUsersMixin, DetailView):
    template_name = "accounts/user_api_token.html"

    def get_queryset(self):
        min_created = datetime.now() - timedelta(seconds=30)
        return User.objects.filter(auth_token__created__gte=min_created)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        user = ctx["user"]
        ctx["title"] = "{} API token".format(user.get_type_display().title())
        return ctx


class DeleteUserAPITokenView(CanManageUsersMixin, TemplateView):
    template_name = "accounts/api_token_confirm_delete.html"

    def dispatch(self, request, *args, **kwargs):
        self.user = get_object_or_404(User, pk=kwargs["pk"])
        if not Token.objects.filter(user=self.user).count():
            messages.warning(request, "User has no API token")
            return redirect("users:user", self.user.pk)
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["user"] = self.user
        return ctx

    def post(self, request, *args, **kwargs):
        deleted_token_count, _ = Token.objects.filter(user=self.user).delete()
        if deleted_token_count:
            messages.info(request, "User API token deleted")
        else:
            messages.warning(request, "No API token deleted")
        return redirect("users:user", self.user.pk)


class UpdateUserView(CanManageUsersMixin, FormView):
    template_name = "accounts/user_form.html"
    form_class = UpdateUserForm

    def dispatch(self, request, *args, **kwargs):
        self.user = get_object_or_404(User, pk=kwargs["pk"])
        if not self.user.editable():
            return HttpResponseRedirect(self.success_url)
        return super().dispatch(request, *args, **kwargs)

    def get_form_class(self):
        if self.user.is_service_account:
            return ServiceAccountForm
        else:
            return UpdateUserForm

    def get_initial(self):
        if self.user.is_service_account:
            return {"name": self.user.username}
        else:
            return {"username": self.user.username,
                    "email": self.user.email,
                    "is_superuser": self.user.is_superuser}

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["instance"] = self.user
        return kwargs

    def form_valid(self, form):
        form.save(self.request)
        return redirect("users:user", self.user.pk)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["user"] = self.user
        ctx["title"] = "Update {} {}".format(self.user.get_type_display(), self.user)
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
        ctx["setup"] = True
        ctx["user"] = self.user
        ctx["title"] = "Delete {}".format(self.user.get_type_display())
        return ctx

    def post(self, request, *args, **kwargs):
        if self.user.is_service_account:
            msg = "Service account {} deleted".format(self.user)
        else:
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
