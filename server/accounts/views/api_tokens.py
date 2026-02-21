import logging

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render, reverse
from django.views.generic import CreateView, TemplateView

from accounts.forms import APITokenForm
from accounts.models import APIToken, User
from zentral.core.events.base import AuditEvent
from zentral.utils.views import UpdateViewWithAudit

logger = logging.getLogger("zentral.accounts.views.api_tokens")


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
        if request.user == self.user:
            return redirect("accounts:profile")
        else:
            return redirect(self.user)
