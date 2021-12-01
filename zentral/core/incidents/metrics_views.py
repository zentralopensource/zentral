import logging
from django.db import connection
from prometheus_client import Gauge
from zentral.utils.prometheus import BasePrometheusMetricsView
from .models import Severity, Status


logger = logging.getLogger("zentral.core.incidents.metrics_views")


class MetricsView(BasePrometheusMetricsView):
    def populate_registry(self):
        g = Gauge('zentral_incidents', 'Zentral incidents',
                  ['type', 'severity', 'status', 'opened'],
                  registry=self.registry)
        query = (
            "select count(*), "
            "i.incident_type as type, i.severity, "
            "mi.status, (CASE WHEN mi.status in ('CLOSED', 'RESOLVED') THEN FALSE ELSE TRUE END) as opened "
            "from incidents_incident as i "
            "join incidents_machineincident as mi on (mi.incident_id = i.id) "
            "group by i.incident_type, i.severity, mi.status, opened "
            "order by i.incident_type, mi.status;"
        )
        cursor = connection.cursor()
        cursor.execute(query)
        columns = [col[0] for col in cursor.description]
        for row in cursor.fetchall():
            d = dict(zip(columns, row))
            try:
                d["severity"] = str(Severity(d.pop("severity")))
            except ValueError:
                d["severity"] = "Unknown"
            try:
                d["status"] = str(Status(d.pop("status")))
            except ValueError:
                d["status"] = "Unknown"
            d["opened"] = 'Y' if d["opened"] else 'N'
            count = d.pop('count')
            g.labels(**d).set(count)
