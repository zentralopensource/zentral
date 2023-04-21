import logging
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.core.exceptions import PermissionDenied
from django.views.generic import TemplateView, View
from zentral.contrib.osquery.models import Configuration
from zentral.contrib.osquery.terraform import iter_resources
from zentral.utils.terraform import build_config_response


logger = logging.getLogger('zentral.contrib.osquery.views.index')


class IndexView(LoginRequiredMixin, TemplateView):
    template_name = "osquery/index.html"

    def get_context_data(self, **kwargs):
        if not self.request.user.has_module_perms("osquery"):
            raise PermissionDenied("Not allowed")
        ctx = super().get_context_data(**kwargs)
        ctx["configurations"] = Configuration.objects.all()
        ctx["configuration_count"] = ctx["configurations"].count()
        ctx["show_terraform_export"] = all(
            self.request.user.has_perm(perm)
            for perm in TerraformExportView.permission_required
        )
        return ctx


class TerraformExportView(PermissionRequiredMixin, View):
    permission_required = (
        "osquery.view_automatictableconstruction",
        "osquery.view_configuration",
        "osquery.view_configurationpack",
        "osquery.view_enrollment",
        "osquery.view_filecategory",
        "osquery.view_pack",
        "osquery.view_packquery",
        "osquery.view_query",
    )

    def get(self, request, *args, **kwargs):
        return build_config_response(iter_resources(), "terraform_osquery")
