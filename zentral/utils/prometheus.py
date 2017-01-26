import logging
from prometheus_client import start_http_server


logger = logging.getLogger("zentral.utils.prometheus")


class PrometheusWorkerMixin(object):
    def setup_prometheus_metrics(self):
        pass

    def start_prometheus_server(self, port):
        self.setup_prometheus_metrics()
        logger.info("Starting prometheus http server on port %s", port)
        start_http_server(port)
