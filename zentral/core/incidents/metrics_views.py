import logging
from django.db import connection
from prometheus_client import Gauge
from zentral.utils.prometheus import BasePrometheusMetricsView
from .models import Severity, Status


logger = logging.getLogger("zentral.core.incidents.metrics_views")


class MetricsView(BasePrometheusMetricsView):
    def populate_registry(self):
        ig = Gauge(
            'zentral_incidents', 'Zentral incidents',
            ['type', 'severity', 'status'],
            registry=self.registry
        )
        mig = Gauge(
            'zentral_machine_incidents', 'Zentral machine incidents',
            ['type', 'severity', 'status'],
            registry=self.registry
        )
        query = (
            "select count(distinct i.id) as incident_count,"
            "count(*) as machine_count,"
            "i.incident_type as type, i.severity, mi.status "
            "from incidents_incident as i "
            "join incidents_machineincident as mi on (mi.incident_id = i.id) "
            "group by i.incident_type, i.severity, mi.status"
        )
        cursor = connection.cursor()
        cursor.execute(query)
        columns = [col[0] for col in cursor.description]
        for row in cursor.fetchall():
            d = dict(zip(columns, row))
            incident_count = d.pop('incident_count')
            machine_count = d.pop('machine_count')
            try:
                d["severity"] = Severity(d.pop("severity")).name.lower()
            except ValueError:
                d["severity"] = "-"
            try:
                d["status"] = Status(d.pop("status")).name.lower()
            except ValueError:
                d["status"] = "-"
            ig.labels(**d).set(incident_count)
            mig.labels(**d).set(machine_count)
