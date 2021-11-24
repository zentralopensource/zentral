import logging
from django.db import connection
from prometheus_client import Gauge
from zentral.utils.prometheus import BasePrometheusMetricsView
from .models import SEVERITY_CHOICES_DICT, STATUS_CHOICES_DICT


logger = logging.getLogger("zentral.core.incidents.metrics_views")


class MetricsView(BasePrometheusMetricsView):
    def populate_registry(self):
        g = Gauge('zentral_incidents', 'Zentral incidents',
                  ['name', 'id', 'severity', 'status', 'opened'],
                  registry=self.registry)
        query = (
            "select count(*), "
            "i.id, i.name, i.severity, "
            "mi.status, (CASE WHEN mi.status in ('CLOSED', 'RESOLVED') THEN FALSE ELSE TRUE END) as opened "
            "from incidents_incident as i "
            "join incidents_machineincident as mi on (mi.incident_id = i.id) "
            "group by i.name, i.id, i.severity, mi.status, opened "
            "order by i.id, mi.status;"
        )
        cursor = connection.cursor()
        cursor.execute(query)
        columns = [col[0] for col in cursor.description]
        for row in cursor.fetchall():
            d = dict(zip(columns, row))
            d["severity"] = str(SEVERITY_CHOICES_DICT.get(d.pop("severity"), "Unknown"))
            d["status"] = str(STATUS_CHOICES_DICT.get(d.pop("status"), "Unknown"))
            d["opened"] = 'Y' if d["opened"] else 'N'
            count = d.pop('count')
            g.labels(**d).set(count)
