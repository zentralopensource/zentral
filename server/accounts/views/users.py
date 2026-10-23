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
from accounts.models import Policy, User
from pbac.entities import Principal
from realms.models import get_matching_realm_users
from zentral.core.events.base import AuditEvent
from zentral.utils.views import (CreateViewWithAudit, LocalUserRequiredMixin, RequestUserFormMixin,
                                 UpdateViewWithAudit)

logger = logging.getLogger("zentral.accounts.views.users")


class UsersView(PermissionRequiredMixin, TemplateView):
    permission_required = 'accounts.view_user'
    template_name = "accounts/user_list.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        users = list(User.objects.filter(is_service_account=False))
        if self.request.user.has_perm("realms.view_realmuser"):
            matching_realm_users = get_matching_realm_users(users)
            for user in users:
                user.realm_users = matching_realm_users[user.pk]
        ctx["users"] = users
        ctx["user_count"] = len(users)
        ctx["service_accounts"] = User.objects.filter(is_service_account=True)
        ctx["service_account_count"] = ctx["service_accounts"].count()
        return ctx


class InviteUserView(LocalUserRequiredMixin, PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = 'accounts.add_user'
    template_name = "accounts/user_form.html"
    form_class = InviteUserForm
    success_url = reverse_lazy("accounts:users")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "Send an email invitation"
        return ctx


class CreateServiceAccountView(LocalUserRequiredMixin, PermissionRequiredMixin, RequestUserFormMixin,
                               CreateViewWithAudit):
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
        # gates the add and change flags below, not the delete one
        can_issue_credentials = (
            self.object.is_service_account and self.request.user.can_issue_credentials_for(self.object)
        )
        ctx["can_manage_oidc_api_token_issuers"] = can_issue_credentials
        ctx["tokens"] = self.object.apitoken_set.all()
        ctx["token_count"] = ctx["tokens"].count()
        ctx["can_delete_token"] = (
            self.object == self.request.user or self.request.user.has_perm("accounts.delete_apitoken")
        )
        ctx["can_change_token"] = (
            self.object == self.request.user
            or (can_issue_credentials and self.request.user.has_perm("accounts.change_apitoken"))
        )
        ctx["can_add_token"] = (
            self.object == self.request.user
            or (can_issue_credentials and self.request.user.has_perm("accounts.add_apitoken"))
        )
        ctx["verification_devices"] = self.object.get_verification_devices()
        ctx["verification_device_count"] = len(ctx["verification_devices"])
        ctx["pbac_principal"] = str(Principal.from_user(self.object))
        # PBAC policies that reference this user (either User::"<pk>"
        # or ServiceAccount::"<pk>").
        policies = Policy.objects.referencing_user(self.object.pk)
        ctx["policies"] = policies
        ctx["policy_count"] = policies.count()
        if not self.object.is_service_account and self.request.user.has_perm("realms.view_realmuser"):
            ctx["realm_users"] = get_matching_realm_users([self.object])[self.object.pk]
        return ctx


class UpdateUserView(LocalUserRequiredMixin, PermissionRequiredMixin, RequestUserFormMixin, UpdateViewWithAudit):
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


class DeleteUserView(LocalUserRequiredMixin, PermissionRequiredMixin, TemplateView):
    permission_required = "accounts.delete_user"
    template_name = "accounts/delete_user.html"

    # not in dispatch: the user is loaded after the login and permission checks of the mixins,
    # so that a request without them cannot tell an unknown id from a superuser
    def load_user(self):
        self.user = get_object_or_404(User, pk=self.kwargs["pk"])
        return self.user.deletable()

    def get(self, request, *args, **kwargs):
        if not self.load_user():
            return redirect("accounts:users")
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["user_to_delete"] = self.user
        ctx["title"] = "Delete {}".format(self.user.get_type_display())
        return ctx

    def post(self, request, *args, **kwargs):
        if not self.load_user():
            return redirect("accounts:users")
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
