from django.http import HttpResponse
from django.views import generic
from zentral.conf import probes
from zentral.contrib.osquery.models import DistributedQuery
from zentral.core.stores import stores


class HealthCheckView(generic.View):
    def get(self, request, *args, **kwargs):
        return HttpResponse('OK')


class IndexView(generic.TemplateView):
    template_name = "base/index.html"

    def get_context_data(self, **kwargs):
        context = super(IndexView, self).get_context_data(**kwargs)
        return context
