import logging
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.views.generic.base import RedirectView
from .models import ComplianceCheck


logger = logging.getLogger("zentral.core.compliance_checks.views")


class ComplianceCheckRedirectView(PermissionRequiredMixin, RedirectView):
    permission_required = "compliance_checks.view_compliancecheck"

    def get_redirect_url(*args, **kwargs):
        compliance_check = get_object_or_404(ComplianceCheck, pk=kwargs["pk"])
        try:
            return compliance_check.loaded_compliance_check.get_redirect_url()
        except Exception:
            logger.exception("Could not get compliance check %s redirect url", compliance_check.pk)
            raise Http404
