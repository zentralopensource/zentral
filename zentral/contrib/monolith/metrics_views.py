from prometheus_client import Gauge
from zentral.utils.prometheus import BasePrometheusMetricsView
from .models import PkgInfo


class MetricsView(BasePrometheusMetricsView):
    def populate_registry(self):
        g = Gauge('zentral_monolith_pkginfos', 'Zentral Monolith Pkginfos',
                  ['name', 'version'],
                  registry=self.registry)
        _, _, pkg_names = PkgInfo.objects.alles()
        for pkg_name in pkg_names:
            name = pkg_name["name"]
            for pkg_info in pkg_name["pkg_infos"]:
                g.labels(name=name, version=pkg_info["version"]).set(pkg_info["count"])
