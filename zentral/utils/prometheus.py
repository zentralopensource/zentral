import logging
from django.http import HttpResponse, HttpResponseForbidden
from django.views import View
from prometheus_client import start_http_server, CONTENT_TYPE_LATEST, generate_latest
from zentral.conf import settings


logger = logging.getLogger("zentral.utils.prometheus")


class PrometheusWorkerMixin(object):
    def setup_prometheus_metrics(self):
        pass

    def start_prometheus_server(self, port):
        self.setup_prometheus_metrics()
        logger.info("Starting prometheus http server on port %s", port)
        start_http_server(port)


class BasePrometheusMetricsView(View):
    def get_registry(self):
        pass

    def get(self, request, *args, **kwargs):
        bearer_token = settings['apps']['zentral.contrib.inventory'].get('prometheus_bearer_token')
        if bearer_token and request.META.get('HTTP_AUTHORIZATION') == "Bearer {}".format(bearer_token):
            content = ""
            registry = self.get_registry()
            if registry is not None:
                content = generate_latest(registry)
            return HttpResponse(content, content_type=CONTENT_TYPE_LATEST)
        else:
            return HttpResponseForbidden()
