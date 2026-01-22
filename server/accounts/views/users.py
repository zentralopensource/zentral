import logging

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models.functions import Lower
from django.shortcuts import get_object_or_404, redirect, render, reverse
from django.urls import reverse_lazy
from django.views.generic import CreateView, DetailView, TemplateView

from accounts.events import post_group_membership_updates
from accounts.forms import (
    APITokenForm,
    InviteUserForm,
    ServiceAccountForm,
    UpdateUserForm,
)
from accounts.models import APIToken, User
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
        ctx["tokens"] = self.object.apitoken_set.all()
        ctx["group_count"] = groups.count()
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
        return ctx


class CreateUserAPITokenView(LoginRequiredMixin, CreateView):
    template_name = "accounts/token_form.html"
    form_class = APITokenForm

    def dispatch(self, request, *args, **kwargs):
        self.user = User.objects.get(pk=kwargs['user_pk'])
        if (
            self.user != self.request.user
            and (not self.user.is_service_account or not self.request.user.has_perms(("accounts.add_apitoken",)))
        ):
            raise PermissionDenied("Not allowed")

        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.user
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['user'] = self.user
        context["title"] = "Create API token"
        context["breadcrumb_title"] = "API token"
        return context

    def form_valid(self, form):

        api_token, api_key = APIToken.objects.create_for_user(self.user,
                                                              expiry=form.cleaned_data['expiry'],
                                                              name=form.cleaned_data['name'])

        def on_commit_callback():
            event = AuditEvent.build_from_request_and_instance(
                self.request, api_token,
                action=AuditEvent.Action.CREATED,
            )
            event.post()
        transaction.on_commit(on_commit_callback)
        return render(
            self.request,
            "accounts/user_api_token.html",
            {"api_key": api_key,
             "api_token": api_token,
             "object": self.user,
             "title": "User API token"}
        )


class UpdateUserAPITokenView(LoginRequiredMixin, UpdateViewWithAudit):
    template_name = "accounts/token_form.html"
    model = APIToken
    form_class = APITokenForm

    def dispatch(self, request, *args, **kwargs):
        self.user = User.objects.get(pk=kwargs['user_pk'])
        if (
            self.user != self.request.user
            and (not self.user.is_service_account or not self.request.user.has_perms(("accounts.change_apitoken",)))
        ):
            raise PermissionDenied("Not allowed")
        self.token = get_object_or_404(APIToken, user=self.user, id=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['user'] = self.user
        ctx['token'] = self.token
        return ctx

    def get_success_url(self):
        if self.user == self.request.user:
            return reverse("accounts:profile") + f"#apitoken-{self.token.pk}"
        else:
            return reverse("accounts:user", args=(self.user.pk,)) + f"#apitoken-{self.token.pk}"


class DeleteUserAPITokenView(LoginRequiredMixin, TemplateView):
    template_name = "accounts/api_token_confirm_delete.html"

    def dispatch(self, request, *args, **kwargs):
        self.user = get_object_or_404(User, pk=kwargs["user_pk"])
        if (
            self.user != self.request.user and not self.request.user.has_perms(("accounts.delete_apitoken",))
        ):
            raise PermissionDenied("Not allowed")
        self.token = get_object_or_404(APIToken, user=self.user, id=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["token_user"] = self.user
        ctx["token"] = self.token
        return ctx

    def post(self, request, *args, **kwargs):
        token = self.token
        event = AuditEvent.build_from_request_and_instance(
                request, token,
                action=AuditEvent.Action.DELETED,
                prev_value=token.serialize_for_event()
            )
        deleted_token_count, _ = token.delete()

        def on_commit_callback():
            event.post()

        transaction.on_commit(on_commit_callback)

        if deleted_token_count:
            messages.info(request, "User API token deleted")
        else:
            messages.warning(request, "No API token deleted")
        if request.user == self.user:
            return redirect("accounts:profile")
        else:
            return redirect(self.user)


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
