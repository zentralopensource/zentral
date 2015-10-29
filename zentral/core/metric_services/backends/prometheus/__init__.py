from prometheus_client import CollectorRegistry, Gauge, push_to_gateway
from ..base import BaseMetricService
from .utils import GatewayClient


class MetricService(BaseMetricService):
    def __init__(self, config_d):
        self.config_d = config_d
        self._gw_host = config_d['gateway_host']
        self._gw_client = GatewayClient(self._gw_host)

    def push_metrics(self, job_name, metrics, grouping_key=None):
        registry = CollectorRegistry()
        for md in metrics:
            gauges = md.get('gauges', None)
            if gauges:
                # TODO: Job name ?
                # If same job name, problem with registry and only last metric in GW
                self._push_gauges(job_name, md['name'], md['help_text'], gauges, registry, grouping_key)
            else:
                raise ValueError('Unknown metric type %s', md)

    def _push_gauges(self, job_name, metric_name, metric_help_text, gauges, registry, grouping_key):
        if not grouping_key:
            # Add zeroed values to gauges
            for md in self._gw_client.get_metrics(prefix=metric_name):
                labels = md['labels']
                labels.pop('instance', None)  # automatically added by prometheus_client
                labels.pop('job', None)
                key = frozenset(labels.items())
                if key not in gauges and md['value'] != 0:
                    gauges[key] = 0
        if not gauges:
            return
        g = None
        for key, val in gauges.items():
            labels = dict(key)
            if not g:
                g = Gauge(metric_name, metric_help_text, list(labels.keys()), registry=registry)
            g.labels(labels).set(val)
        try:
            push_to_gateway(self._gw_host, job=job_name, registry=registry, grouping_key=grouping_key)
        except:
            raise
