import logging

from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db import transaction
from django.db.models.functions import Lower
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.views.generic import DetailView, TemplateView

from accounts.events import post_group_membership_updates
from accounts.forms import (
    InviteUserForm,
    ServiceAccountForm,
    UpdateUserForm,
)
from accounts.models import User
from zentral.core.events.base import AuditEvent
from zentral.utils.views import CreateViewWithAudit, UpdateViewWithAudit

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


class InviteUserView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = 'accounts.add_user'
    template_name = "accounts/user_form.html"
    form_class = InviteUserForm
    success_url = reverse_lazy("accounts:users")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "Send an email invitation"
        return ctx


class CreateServiceAccountView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = ('accounts.add_user',)
    template_name = "accounts/user_form.html"
    form_class = ServiceAccountForm

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
        ctx["oidc_api_token_issuers"] = self.object.oidcapitokenissuer_set.all()
        ctx["oidc_api_token_issuer_count"] = ctx["oidc_api_token_issuers"].count()
        ctx["tokens"] = self.object.apitoken_set.all()
        ctx["token_count"] = ctx["tokens"].count()
        ctx["can_delete_token"] = (
            self.object == self.request.user or self.request.user.has_perm("accounts.delete_apitoken")
        )
        ctx["can_change_token"] = (
            self.object == self.request.user
            or (self.object.is_service_account and self.request.user.has_perm("accounts.change_apitoken"))
        )
        ctx["can_add_token"] = (
            self.object == self.request.user
            or (self.object.is_service_account and self.request.user.has_perm("accounts.add_apitoken"))
        )
        ctx["verification_devices"] = self.object.get_verification_devices()
        ctx["verification_device_count"] = len(ctx["verification_devices"])
        return ctx


class UpdateUserView(PermissionRequiredMixin, UpdateViewWithAudit):
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
        event = AuditEvent.build_from_request_and_instance(
                request, self.user,
                action=AuditEvent.Action.DELETED,
                prev_value=self.user.serialize_for_event()
            )
        self.user.delete()

        def on_commit_callback():
            event.post()

        transaction.on_commit(on_commit_callback)

        messages.info(request, msg)
        return redirect("accounts:users")
