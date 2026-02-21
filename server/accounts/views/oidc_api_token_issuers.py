import logging

from django.contrib.auth.mixins import PermissionRequiredMixin
from django.shortcuts import get_object_or_404
from django.views.generic import DetailView

from accounts.forms import OIDCAPITokenIssuerForm
from accounts.models import OIDCAPITokenIssuer, User
from zentral.utils.views import CreateViewWithAudit, DeleteViewWithAudit, UpdateViewWithAudit

logger = logging.getLogger("zentral.accounts.views.oidc_api_token_issuers")


class OIDCAPITokenIssuerMixin(PermissionRequiredMixin):
    model = OIDCAPITokenIssuer

    def dispatch(self, request, *args, **kwargs):
        self.service_account = get_object_or_404(User, pk=kwargs["user_pk"], is_service_account=True)
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        return super().get_queryset().filter(user=self.service_account).select_related("user")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["service_account"] = self.service_account
        return ctx


class OIDCAPITokenIssuerFormMixin(OIDCAPITokenIssuerMixin):
    form_class = OIDCAPITokenIssuerForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["service_account"] = self.service_account
        return kwargs


class OIDCAPITokenIssuerView(OIDCAPITokenIssuerMixin, DetailView):
    permission_required = "accounts.view_oidcapitokenissuer"


class CreateOIDCAPITokenIssuerView(OIDCAPITokenIssuerFormMixin, CreateViewWithAudit):
    permission_required = "accounts.add_oidcapitokenissuer"


class UpdateOIDCAPITokenIssuerView(OIDCAPITokenIssuerFormMixin, UpdateViewWithAudit):
    permission_required = "accounts.change_oidcapitokenissuer"


class DeleteOIDCAPITokenIssuerView(OIDCAPITokenIssuerMixin, DeleteViewWithAudit):
    permission_required = "accounts.delete_oidcapitokenissuer"

    def get_success_url(self):
        return self.service_account.get_absolute_url()
