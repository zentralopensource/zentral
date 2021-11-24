from prometheus_client import Gauge
from zentral.utils.prometheus import BasePrometheusMetricsView
from .utils import osx_app_count, os_version_count


class MetricsView(BasePrometheusMetricsView):
    def populate_registry(self):
        g = Gauge('zentral_inventory_osx_apps', 'Zentral inventory OSX apps',
                  ['name', 'version_str', 'source'],
                  registry=self.registry)
        for r in osx_app_count():
            count = r.pop('count')
            g.labels(**r).set(count)
        g = Gauge('zentral_inventory_os_versions', 'Zentral inventory OS Versions',
                  ['name', 'major', 'minor', 'patch', 'build', 'source'],
                  registry=self.registry)
        for r in os_version_count():
            count = r.pop('count')
            g.labels(**r).set(count)
