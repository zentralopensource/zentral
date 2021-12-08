from django.db import connection
from django.db.models import Count
from prometheus_client import Gauge
from zentral.utils.prometheus import BasePrometheusMetricsView
from .models import ManagedInstall


class MetricsView(BasePrometheusMetricsView):
    def add_installed_pkginfos_buckets(self):
        query = (
            "with active_machines as ("
            "  select machine_serial_number, date_part('days', now() - last_seen) as age"
            "  from munki_munkistate"
            "), installed_versions as ("
            "  select mi.name, mi.installed_version as version,"
            '  case when am.age <= 1 then 1 else 0 end as "1",'
            '  case when am.age <= 7 then 1 else 0 end as "7",'
            '  case when am.age <= 14 then 1 else 0 end as "14",'
            '  case when am.age <= 30 then 1 else 0 end as "30",'
            '  case when am.age <= 45 then 1 else 0 end as "45",'
            '  case when am.age <= 90 then 1 else 0 end as "90"'
            "  from munki_managedinstall as mi"
            "  join active_machines as am on (am.machine_serial_number = mi.machine_serial_number)"
            "  where mi.installed_version is not null"
            ") "
            "select name, version,"
            'sum("1") as "1",'
            'sum("7") as "7",'
            'sum("14") as "14",'
            'sum("30") as "30",'
            'sum("45") as "45",'
            'sum("90") as "90",'
            'sum(1) as "+Inf" '
            "from installed_versions "
            "group by name, version"
        )
        cursor = connection.cursor()
        cursor.execute(query)
        columns = [c.name for c in cursor.description]

        g = Gauge('zentral_munki_installed_pkginfos_bucket', 'Zentral Munki installed pkginfos',
                  ['name', 'version', 'le'],
                  registry=self.registry)
        for row in cursor.fetchall():
            row_d = dict(zip(columns, row))
            for le in ("1", "7", "14", "30", "45", "90", "+Inf"):
                g.labels(
                    name=row_d["name"],
                    version=row_d["version"],
                    le=le
                ).set(
                    row_d[le]
                )

    def add_failed_pkginfos(self):
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

    def populate_registry(self):
        self.add_installed_pkginfos_buckets()
        self.add_failed_pkginfos()
