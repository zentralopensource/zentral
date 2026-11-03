import logging

from django.contrib.auth.mixins import PermissionRequiredMixin
from django.shortcuts import get_object_or_404
from django.utils.functional import cached_property
from django.views.generic import DetailView

from accounts.forms import OIDCAPITokenIssuerForm
from accounts.models import OIDCAPITokenIssuer, User
from zentral.utils.views import CreateViewWithAudit, DeleteViewWithAudit, UpdateViewWithAudit, is_local_superuser

logger = logging.getLogger("zentral.accounts.views.oidc_api_token_issuers")


class OIDCAPITokenIssuerMixin(PermissionRequiredMixin):
    model = OIDCAPITokenIssuer

    @cached_property
    def service_account(self):
        # read by the handlers only, after the login and the permission checks of PermissionRequiredMixin.dispatch:
        # a refused request cannot tell which ids are service accounts
        return get_object_or_404(User, pk=self.kwargs["user_pk"], is_service_account=True)

    def get_queryset(self):
        return super().get_queryset().filter(user=self.service_account).select_related("user")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["service_account"] = self.service_account
        ctx["can_manage_oidc_api_token_issuers"] = is_local_superuser(self.request)
        return ctx


class OIDCAPITokenIssuerWriteMixin(OIDCAPITokenIssuerMixin):
    def has_permission(self):
        # until the delegated administration, a superuser writes the credentials of a service account
        return is_local_superuser(self.request)


class OIDCAPITokenIssuerFormMixin(OIDCAPITokenIssuerWriteMixin):
    form_class = OIDCAPITokenIssuerForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["service_account"] = self.service_account
        return kwargs


class OIDCAPITokenIssuerView(OIDCAPITokenIssuerMixin, DetailView):
    permission_required = "accounts.view_oidcapitokenissuer"


class CreateOIDCAPITokenIssuerView(OIDCAPITokenIssuerFormMixin, CreateViewWithAudit):
    pass


class UpdateOIDCAPITokenIssuerView(OIDCAPITokenIssuerFormMixin, UpdateViewWithAudit):
    pass


class DeleteOIDCAPITokenIssuerView(OIDCAPITokenIssuerWriteMixin, DeleteViewWithAudit):

    def get_success_url(self):
        return self.service_account.get_absolute_url()
