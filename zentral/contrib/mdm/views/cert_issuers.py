import logging
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.views.generic import DetailView
from zentral.contrib.mdm.models import ACMEIssuer, SCEPIssuer
from zentral.utils.views import UserPaginationListView


logger = logging.getLogger('zentral.contrib.mdm.views.cert_issuers')


# ACME issuers


class ACMEIssuerListView(PermissionRequiredMixin, UserPaginationListView):
    permission_required = "mdm.view_acmeissuer"
    model = ACMEIssuer


class ACMEIssuerView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_acmeissuer"
    model = ACMEIssuer


# SCEP issuers


class SCEPIssuerListView(PermissionRequiredMixin, UserPaginationListView):
    permission_required = "mdm.view_scepissuer"
    model = SCEPIssuer


class SCEPIssuerView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_scepissuer"
    model = SCEPIssuer
