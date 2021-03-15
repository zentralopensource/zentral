import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.views.generic import TemplateView
from zentral.contrib.osquery.models import Configuration


logger = logging.getLogger('zentral.contrib.osquery.views.index')


class IndexView(LoginRequiredMixin, TemplateView):
    model = Configuration
    template_name = "osquery/index.html"

    def get_context_data(self, **kwargs):
        if not self.request.user.has_module_perms("osquery"):
            raise PermissionDenied("Not allowed")
        ctx = super().get_context_data(**kwargs)
        ctx["configurations"] = Configuration.objects.all()
        ctx["configuration_count"] = ctx["configurations"].count()
        return ctx
