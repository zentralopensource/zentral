from django.conf import settings
from django.contrib import messages
from django.contrib.auth import REDIRECT_FIELD_NAME, login as auth_login
from django.contrib.auth.forms import AuthenticationForm
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
from .forms import AddTOTPForm, AddUserForm, CheckPasswordForm, UpdateUserForm, VerifyForm
from .models import User, UserTOTP


@sensitive_post_parameters()
@csrf_protect
@never_cache
def login(request):
    """
    Displays the login form and handles the login action.
    """
    redirect_to = request.POST.get(REDIRECT_FIELD_NAME,
                                   request.GET.get(REDIRECT_FIELD_NAME, ''))

    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()

            # Ensure the user-originating redirection url is safe.
            if not is_safe_url(url=redirect_to, host=request.get_host()):
                redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)

            if user.has_verification_device():
                # Redirect to verification page
                token = signing.dumps({"auth_backend": user.backend,
                                       "redirect_to": redirect_to,
                                       "user_id": user.id},
                                      salt="zentral_verify_token",
                                      key=settings.SECRET_KEY)
                request.session["verification_token"] = token
                return HttpResponseRedirect(reverse("verify"))
            else:
                # Okay, security check complete. Log the user in.
                auth_login(request, form.get_user())

                return HttpResponseRedirect(redirect_to)
    else:
        form = AuthenticationForm(request)

    context = {
        'form': form,
        REDIRECT_FIELD_NAME: redirect_to,
    }

    return TemplateResponse(request, "registration/login.html", context)


class VerifyView(FormView):
    template_name = "registration/verify.html"
    form_class = VerifyForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["token"] = self.request.session["verification_token"]
        return kwargs

    def form_valid(self, form):
        auth_login(self.request, form.user)  # form.user has the backend (carried by the token from the login view)
        return HttpResponseRedirect(form.redirect_to)


class CanManageUsersMixin(PermissionRequiredMixin):
    permission_required = ('accounts.add_user', 'accounts.change_user', 'accounts.delete_user')


class UsersView(CanManageUsersMixin, ListView):
    model = User


class NginxAuthRequestView(View):
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated():
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
        form.save()
        return super().form_valid(form)


class DeleteTOTPView(LoginRequiredMixin, FormView):
    template_name = "accounts/delete_totp.html"
    form_class = CheckPasswordForm
    success_url = reverse_lazy("users:verification_devices")

    def dispatch(self, request, *args, **kwargs):
        self.user_totp = get_object_or_404(UserTOTP, user=self.request.user, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["object"] = self.user_totp
        return ctx

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form):
        self.user_totp.delete()
        return super().form_valid(form)
