import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import FormView
from .forms import AuditShipperForm
from .osx_package.builder import AuditZentralShipperPkgBuilder

logger = logging.getLogger('zentral.contrib.audit.views')


class InstallerView(LoginRequiredMixin, FormView):
    form_class = AuditShipperForm
    template_name = "audit/installer.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["setup"] = True
        return context

    def form_valid(self, form):
        builder = AuditZentralShipperPkgBuilder(None, **form.get_build_kwargs())
        return builder.build_and_make_response()
