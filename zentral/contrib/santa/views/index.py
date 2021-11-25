import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.views.generic import TemplateView
from zentral.contrib.santa.models import Configuration, Target


logger = logging.getLogger('zentral.contrib.santa.views.index')


class IndexView(LoginRequiredMixin, TemplateView):
    template_name = "santa/index.html"

    def get_context_data(self, **kwargs):
        if not self.request.user.has_module_perms("santa"):
            raise PermissionDenied("Not allowed")
        ctx = super().get_context_data(**kwargs)
        ctx["configurations"] = Configuration.objects.summary()
        ctx["configuration_count"] = len(ctx["configurations"])
        ctx["targets"] = Target.objects.summary()
        return ctx
