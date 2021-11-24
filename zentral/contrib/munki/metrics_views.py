from django.db.models import Count
from prometheus_client import Gauge
from zentral.utils.prometheus import BasePrometheusMetricsView
from .models import ManagedInstall


class MetricsView(BasePrometheusMetricsView):
    def populate_registry(self):
        g = Gauge('zentral_munki_pkginfos', 'Zentral Munki Pkginfos',
                  ['name', 'version'],
                  registry=self.registry)
        for managed_install in (ManagedInstall.objects.values("pkg_info_name", "pkg_info_version")
                                              .annotate(count=Count("machine_serial_number"))):
            g.labels(name=managed_install["pkg_info_name"], version=managed_install["pkg_info_version"]).set(
                managed_install["count"]
            )
