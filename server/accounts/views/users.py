from datetime import datetime, timedelta
import logging
from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse, reverse_lazy
from django.views.generic import DetailView, FormView, TemplateView, View
from rest_framework.authtoken.models import Token
from accounts.forms import InviteUserForm, ServiceAccountForm, UpdateUserForm
from accounts.models import User


logger = logging.getLogger("zentral.accounts.views.users")


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


class InviteUserView(CanManageUsersMixin, FormView):
    template_name = "accounts/user_form.html"
    form_class = InviteUserForm
    success_url = reverse_lazy("accounts:users")

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
    success_url = reverse_lazy("accounts:users")

    def form_valid(self, form):
        user = form.save(self.request)
        return redirect("accounts:user_api_token", user.pk)

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
            return redirect("accounts:users")
        else:
            return redirect("accounts:user_api_token", user.pk)


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
            return redirect("accounts:user", self.user.pk)
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
        return redirect("accounts:user", self.user.pk)


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
        return redirect("accounts:user", self.user.pk)

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
            return HttpResponseRedirect(reverse("accounts:users"))
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
        return HttpResponseRedirect(reverse("accounts:users"))
