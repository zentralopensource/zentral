from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.views.generic import TemplateView
from ..models import Configuration


class IndexView(LoginRequiredMixin, TemplateView):
    # Turbo overview: event aggregations + the configurations with their job / enrollment / machine counts
    template_name = "turbo/index.html"

    def get_context_data(self, **kwargs):
        if not self.request.user.has_module_perms("turbo"):
            raise PermissionDenied("Not allowed")
        ctx = super().get_context_data(**kwargs)
        if self.request.user.has_perm("turbo.view_configuration"):
            ctx["configurations"] = Configuration.objects.summary()
            ctx["configuration_count"] = len(ctx["configurations"])
        return ctx
