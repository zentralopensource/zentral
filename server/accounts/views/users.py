import logging
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.core import signing
from django.core.exceptions import PermissionDenied
from django.db.models.functions import Lower
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.views.generic import DetailView, FormView, TemplateView, UpdateView, View
from rest_framework.authtoken.models import Token
from accounts.events import post_group_membership_updates
from accounts.forms import InviteUserForm, ServiceAccountForm, UpdateUserForm
from accounts.models import User


logger = logging.getLogger("zentral.accounts.views.users")


class UsersView(PermissionRequiredMixin, TemplateView):
    permission_required = 'accounts.view_user'
    template_name = "accounts/user_list.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["users"] = User.objects.filter(is_service_account=False)
        ctx["user_count"] = ctx["users"].count()
        ctx["service_accounts"] = User.objects.filter(is_service_account=True)
        ctx["service_account_count"] = ctx["service_accounts"].count()
        return ctx


class InviteUserView(PermissionRequiredMixin, FormView):
    permission_required = 'accounts.add_user'
    template_name = "accounts/user_form.html"
    form_class = InviteUserForm
    success_url = reverse_lazy("accounts:users")

    def form_valid(self, form):
        form.save(self.request)
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "Send an email invitation"
        return ctx


class CreateServiceAccountView(PermissionRequiredMixin, FormView):
    permission_required = ('accounts.add_user', 'authtoken.add_token')
    template_name = "accounts/user_form.html"
    form_class = ServiceAccountForm
    success_url = reverse_lazy("accounts:users")

    def form_valid(self, form):
        user = form.save(self.request)
        Token.objects.get_or_create(user=user)
        return redirect("accounts:user_api_token", signing.dumps({"uid": user.pk, "aud": "api_token"}))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "Create service account"
        return ctx


class UserView(PermissionRequiredMixin, DetailView):
    permission_required = "accounts.view_user"
    template_name = "accounts/user_detail.html"
    model = User
    # to avoid context collisions
    context_object_name = "object"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "{} {}".format(self.object.get_type_display().title(), self.object)
        groups = self.object.groups.all().order_by(Lower("name"))
        ctx["groups"] = groups
        ctx["group_count"] = groups.count()
        ctx["can_delete_token"] = (
            self.object == self.request.user or self.request.user.has_perm("authtoken.delete_token")
        )
        ctx["can_add_token"] = (
            self.object == self.request.user
            or (self.object.is_service_account and self.request.user.has_perm("authtoken.add_token"))
        )
        ctx["verification_devices"] = self.object.get_verification_devices()
        return ctx


class CreateUserAPITokenView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        user = get_object_or_404(User, pk=kwargs["pk"])
        if (
            user != self.request.user
            and (not user.is_service_account or not self.request.user.has_perms(("accounts.view_user",
                                                                                 "authtoken.add_token")))
        ):
            raise PermissionDenied("Not allowed")
        _, created = Token.objects.get_or_create(user=user)
        if not created:
            messages.warning(request, "User already has an API token")
            return redirect(user)
        else:
            return redirect("accounts:user_api_token", signing.dumps({"uid": user.pk, "aud": "api_token"}))


class UserAPITokenView(LoginRequiredMixin, DetailView):
    template_name = "accounts/user_api_token.html"
    # to avoid context collisions
    context_object_name = "object"

    def get_object(self, queryset=None):
        try:
            signed_data = signing.loads(self.kwargs["signed_pk"], max_age=30)
        except signing.BadSignature:
            raise PermissionDenied("Bad signature")
        if signed_data.get("aud") != "api_token":
            raise PermissionDenied("Bad signed data")
        user = get_object_or_404(User, pk=signed_data["uid"])
        if (
            user != self.request.user
            and (not user.is_service_account or not self.request.user.has_perms(("accounts.view_user",
                                                                                 "authtoken.add_token")))
        ):
            raise PermissionDenied("Not allowed")
        return user

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "{} API token".format(self.object.get_type_display().title())
        return ctx


class DeleteUserAPITokenView(LoginRequiredMixin, TemplateView):
    template_name = "accounts/api_token_confirm_delete.html"

    def dispatch(self, request, *args, **kwargs):
        self.user = get_object_or_404(User, pk=kwargs["pk"])
        if (
            self.user != self.request.user and not self.request.user.has_perms(("accounts.view_user",
                                                                                "authtoken.delete_token"))
        ):
            raise PermissionDenied("Not allowed")
        if not Token.objects.filter(user=self.user).count():
            messages.warning(request, "User has no API token")
            return redirect(self.user)
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["token_user"] = self.user
        return ctx

    def post(self, request, *args, **kwargs):
        deleted_token_count, _ = Token.objects.filter(user=self.user).delete()
        if deleted_token_count:
            messages.info(request, "User API token deleted")
        else:
            messages.warning(request, "No API token deleted")
        if request.user == self.user:
            return redirect("accounts:profile")
        else:
            return redirect(self.user)


class UpdateUserView(PermissionRequiredMixin, UpdateView):
    permission_required = "accounts.change_user"
    model = User
    # to avoid context collisions
    context_object_name = "user_to_update"

    def get_form_class(self):
        if self.object.is_service_account:
            return ServiceAccountForm
        else:
            return UpdateUserForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "Update {} {}".format(self.object.get_type_display(), self.object)
        return ctx

    def form_valid(self, form):
        current_groups = set(self.object.groups.all())
        response = super().form_valid(form)
        new_groups = set(self.object.groups.all())
        if new_groups != current_groups:
            self.object.refresh_from_db()
            post_group_membership_updates(
                self.request, new_groups - current_groups, current_groups - new_groups, self.object
            )
        return response


class DeleteUserView(PermissionRequiredMixin, TemplateView):
    permission_required = "accounts.delete_user"
    template_name = "accounts/delete_user.html"

    def dispatch(self, request, *args, **kwargs):
        self.user = get_object_or_404(User, pk=kwargs["pk"])
        if not self.user.deletable():
            return redirect("accounts:users")
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["user_to_delete"] = self.user
        ctx["title"] = "Delete {}".format(self.user.get_type_display())
        return ctx

    def post(self, request, *args, **kwargs):
        if self.user.is_service_account:
            msg = "Service account {} deleted".format(self.user)
        else:
            msg = "User {} deleted".format(self.user)
        self.user.delete()
        messages.info(request, msg)
        return redirect("accounts:users")
