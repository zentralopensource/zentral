import logging
from django.http import HttpResponse, HttpResponseForbidden
from django.views import View
from prometheus_client import generate_latest, start_http_server, Counter, CONTENT_TYPE_LATEST
from zentral.conf import settings


logger = logging.getLogger("zentral.utils.prometheus")


class PrometheusMetricsExporter:
    def __init__(self, port):
        self.port = port
        self.counters = {}

    def start(self):
        logger.info("Starting prometheus http server on port %s", self.port)
        start_http_server(self.port)

    def add_counter(self, name, labels):
        description = name.replace("_", " ").capitalize()
        self.counters[name] = Counter(name, description, labels)

    def inc(self, counter_name, *label_values):
        try:
            self.counters[counter_name].labels(*label_values).inc()
        except KeyError:
            logger.error("Missing counter %s", counter_name)


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
