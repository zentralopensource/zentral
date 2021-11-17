from zentral.utils.prometheus import BasePrometheusMetricsView
from .utils import get_prometheus_inventory_metrics


class MetricsView(BasePrometheusMetricsView):
    def get_registry(self):
        return get_prometheus_inventory_metrics()
