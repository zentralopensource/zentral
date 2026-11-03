import logging

from django.contrib import messages
from django.contrib.auth.mixins import AccessMixin
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render, reverse
from django.views.generic import CreateView, TemplateView

from accounts.forms import APITokenForm
from accounts.models import APIToken, User
from accounts.utils import delete_api_token
from zentral.core.events.base import AuditEvent
from zentral.utils.views import UpdateViewWithAudit, is_local_superuser

logger = logging.getLogger("zentral.accounts.views.api_tokens")


class UserAPITokenMixin(AccessMixin):
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission()
        # the checks that need no account before the lookup: a refused request cannot tell which ids exist.
        # Until the delegated administration, a superuser makes the tokens of a service account,
        # and deletes the tokens of another account.
        if kwargs["user_pk"] != request.user.pk and not is_local_superuser(request):
            raise PermissionDenied("Not allowed")
        self.user = get_object_or_404(User, pk=kwargs["user_pk"])
        self.check_access()
        return super().dispatch(request, *args, **kwargs)

    def check_token_writer(self):
        # check_access runs in dispatch, after its check: only a local superuser reaches another account here
        if self.user != self.request.user:
            # nobody makes or updates the tokens of another user
            if not self.user.is_service_account:
                raise PermissionDenied("Not allowed")
        elif not self.user.can_have_api_tokens:
            raise PermissionDenied("A superuser has no API token")


class CreateUserAPITokenView(UserAPITokenMixin, CreateView):
    template_name = "accounts/token_form.html"
    form_class = APITokenForm

    def check_access(self):
        self.check_token_writer()

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


class UpdateUserAPITokenView(UserAPITokenMixin, UpdateViewWithAudit):
    template_name = "accounts/token_form.html"
    model = APIToken
    form_class = APITokenForm

    def check_access(self):
        self.check_token_writer()
        self.token = get_object_or_404(APIToken, user=self.user, id=self.kwargs["pk"])

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


class DeleteUserAPITokenView(UserAPITokenMixin, TemplateView):
    template_name = "accounts/api_token_confirm_delete.html"

    def check_access(self):
        # the owner, or a superuser, checked by the mixin
        self.token = get_object_or_404(APIToken, user=self.user, id=self.kwargs["pk"])

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["token_user"] = self.user
        ctx["token"] = self.token
        return ctx

    def post(self, request, *args, **kwargs):
        if delete_api_token(self.token, request):
            messages.info(request, "User API token deleted")
        if request.user == self.user:
            return redirect("accounts:profile")
        else:
            return redirect(self.user)
