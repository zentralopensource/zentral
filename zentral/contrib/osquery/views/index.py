import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from zentral.contrib.osquery.models import Configuration


logger = logging.getLogger('zentral.contrib.osquery.views.index')


class IndexView(LoginRequiredMixin, TemplateView):
    model = Configuration
    template_name = "osquery/index.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["configurations"] = Configuration.objects.all()
        ctx["configuration_count"] = ctx["configurations"].count()
        return ctx
