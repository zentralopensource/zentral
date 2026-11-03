import logging

from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db.models.functions import Lower
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse, reverse_lazy
from django.views.generic import DetailView, TemplateView

from accounts.events import post_group_membership_updates
from accounts.forms import (
    InviteUserForm,
    ServiceAccountForm,
    UpdateUserForm,
)
from accounts.models import Policy, User
from accounts.utils import delete_api_tokens
from pbac.entities import Principal
from realms.models import get_matching_realm_users
from zentral.utils.views import (CreateViewWithAudit, LocalSuperuserRequiredMixin, UpdateViewWithAudit,
                                 is_local_superuser, post_delete_audit_event)

logger = logging.getLogger("zentral.accounts.views.users")


def set_write_urls(request, users):
    # no link to a page that would refuse the request
    can_write = is_local_superuser(request)
    for user in users:
        user.update_url = user.delete_url = None
        if not can_write:
            continue
        user.update_url = reverse("accounts:update_user", args=(user.pk,))
        if user.deletable():
            user.delete_url = reverse("accounts:delete_user", args=(user.pk,))


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
        service_accounts = list(User.objects.filter(is_service_account=True))
        set_write_urls(self.request, users + service_accounts)
        ctx["users"] = users
        ctx["user_count"] = len(users)
        ctx["service_accounts"] = service_accounts
        ctx["service_account_count"] = len(service_accounts)
        return ctx


# Until the delegated administration, a superuser makes each write that gives access. Holding the roles of an
# account is not holding its access: a forbid on a role, and a role given later, escape a comparison of roles.


class InviteUserView(LocalSuperuserRequiredMixin, CreateViewWithAudit):
    template_name = "accounts/user_form.html"
    form_class = InviteUserForm
    success_url = reverse_lazy("accounts:users")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "Send an email invitation"
        return ctx


class CreateServiceAccountView(LocalSuperuserRequiredMixin, CreateViewWithAudit):
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
        set_write_urls(self.request, [self.object])
        groups = self.object.groups.all().order_by(Lower("name"))
        ctx["groups"] = groups
        ctx["group_count"] = groups.count()
        ctx["oidc_api_token_issuers"] = self.object.oidcapitokenissuer_set.all()
        ctx["oidc_api_token_issuer_count"] = ctx["oidc_api_token_issuers"].count()
        # gates the add and change flags below, not the delete one
        can_issue_credentials = self.object.is_service_account and is_local_superuser(self.request)
        ctx["can_manage_oidc_api_token_issuers"] = can_issue_credentials
        ctx["tokens"] = self.object.apitoken_set.all()
        ctx["token_count"] = ctx["tokens"].count()
        ctx["can_delete_token"] = self.object == self.request.user or is_local_superuser(self.request)
        ctx["can_change_token"] = ctx["can_add_token"] = self.object.can_have_api_tokens and (
            self.object == self.request.user or can_issue_credentials
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


class UpdateUserView(LocalSuperuserRequiredMixin, UpdateViewWithAudit):
    model = User
    # to avoid context collisions
    context_object_name = "user_to_update"

    def get_object(self, queryset=None):
        return get_object_or_404(User, pk=self.kwargs["pk"])

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
        if (
            "is_superuser" in form.changed_data
            and not self.object.can_have_api_tokens
            and delete_api_tokens(self.object, self.request)
        ):
            messages.info(self.request, "API tokens of the superuser deleted")
        new_groups = set(self.object.groups.all())
        if new_groups != current_groups:
            self.object.refresh_from_db()
            post_group_membership_updates(
                self.request, new_groups - current_groups, current_groups - new_groups, self.object
            )
        return response


class DeleteUserView(LocalSuperuserRequiredMixin, TemplateView):
    template_name = "accounts/delete_user.html"

    # not in dispatch: the user is loaded after the check of the mixin, so that a refused request
    # cannot tell which ids exist
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
        post_delete_audit_event(request, self.user)
        self.user.delete()
        messages.info(request, msg)
        return redirect("accounts:users")
