import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from zentral.utils.api_views import BaseEnrollmentView, BaseInstallerPackageView
from .osx_package.builder import AuditZentralShipperPkgBuilder

logger = logging.getLogger('zentral.contrib.audit.views')


class EnrollmentView(LoginRequiredMixin, BaseEnrollmentView):
    builder = AuditZentralShipperPkgBuilder
    template_name = "audit/enrollment.html"


class InstallerPackageView(LoginRequiredMixin, BaseInstallerPackageView):
    module = "zentral.contrib.audit"
    builder = AuditZentralShipperPkgBuilder
    template_name = "santa/enrollment.html"
