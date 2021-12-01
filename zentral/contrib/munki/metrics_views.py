from django.db.models import Count
from prometheus_client import Gauge
from zentral.utils.prometheus import BasePrometheusMetricsView
from .models import ManagedInstall


class MetricsView(BasePrometheusMetricsView):
    def populate_registry(self):
        g = Gauge('zentral_munki_installed_pkginfos', 'Zentral Munki installed pkginfos',
                  ['name', 'version', 'reinstall'],
                  registry=self.registry)
        for managed_install in (ManagedInstall.objects
                                              .filter(installed_version__isnull=False)
                                              .values("name", "installed_version", "reinstall")
                                              .annotate(count=Count("machine_serial_number"))):
            g.labels(
                name=managed_install["name"],
                version=managed_install["installed_version"],
                reinstall="yes" if managed_install["reinstall"] else "no",
            ).set(
                managed_install["count"]
            )
        g = Gauge('zentral_munki_failed_pkginfos', 'Zentral Munki failed pkginfos',
                  ['name', 'version'],
                  registry=self.registry)
        for managed_install in (ManagedInstall.objects
                                              .filter(failed_version__isnull=False)
                                              .values("name", "failed_version")
                                              .annotate(count=Count("machine_serial_number"))):
            g.labels(
                name=managed_install["name"],
                version=managed_install["failed_version"],
            ).set(
                managed_install["count"]
            )
