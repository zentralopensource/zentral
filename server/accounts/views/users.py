import logging
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models.functions import Lower
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.views.generic import DetailView, FormView, TemplateView, UpdateView, View
from accounts.events import post_group_membership_updates
from accounts.forms import InviteUserForm, ServiceAccountForm, UpdateUserForm
from accounts.models import APIToken, User
from zentral.core.events.base import AuditEvent


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
    permission_required = ('accounts.add_user', 'accounts.add_apitoken')
    template_name = "accounts/user_form.html"
    form_class = ServiceAccountForm
    success_url = reverse_lazy("accounts:users")

    def form_valid(self, form):
        user = form.save(self.request)
        _, api_key = APIToken.objects.update_or_create_for_user(user)
        return render(
            self.request,
            "accounts/user_api_token.html",
            {"api_key": api_key,
             "object": user,
             "title": "Service account API token"}
        )

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
            self.object == self.request.user or self.request.user.has_perm("accounts.delete_apitoken")
        )
        ctx["can_add_token"] = (
            self.object == self.request.user
            or (self.object.is_service_account and self.request.user.has_perm("accounts.add_apitoken"))
        )
        ctx["verification_devices"] = self.object.get_verification_devices()
        return ctx


class CreateUserAPITokenView(LoginRequiredMixin, View): 
    def post(self, request, *args, **kwargs):
        user = get_object_or_404(User, pk=kwargs["pk"])
        if (
            user != self.request.user
            and (not user.is_service_account or not self.request.user.has_perms(("accounts.view_user",
                                                                                 "accounts.add_apitoken")))
        ):
            raise PermissionDenied("Not allowed")
        if APIToken.objects.filter(user=user).exists():
            messages.warning(request, "User already has an API token")
            return redirect(user)
        api_token, api_key = APIToken.objects.update_or_create_for_user(user)

        def on_commit_callback():
            event = AuditEvent.build_from_request_and_instance(
                request, api_token,
                action=AuditEvent.Action.CREATED,
            )
            event.post()

        transaction.on_commit(on_commit_callback)

        return render(
            request,
            "accounts/user_api_token.html",
            {"api_key": api_key,
             "object": user,
             "title": "User API token"}
        )


class DeleteUserAPITokenView(LoginRequiredMixin, TemplateView): 
    template_name = "accounts/api_token_confirm_delete.html"

    def dispatch(self, request, *args, **kwargs):
        self.user = get_object_or_404(User, pk=kwargs["pk"])
        if (
            self.user != self.request.user and not self.request.user.has_perms(("accounts.view_user",
                                                                                "accounts.delete_apitoken"))
        ):
            raise PermissionDenied("Not allowed")
        if not APIToken.objects.filter(user=self.user).count():
            messages.warning(request, "User has no API token")
            return redirect(self.user)
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["token_user"] = self.user
        return ctx

    def post(self, request, *args, **kwargs):
        tokens = APIToken.objects.filter(user=self.user)
        events = [AuditEvent.build_from_request_and_instance(
                request, token,
                action=AuditEvent.Action.DELETED,
                prev_value=token.serialize_for_event()
            ) for token in tokens.all()]
        deleted_token_count, _ = tokens.delete()

        def on_commit_callback():
            for event in events:
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
