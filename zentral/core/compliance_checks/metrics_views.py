import logging
from django.db import connection
from prometheus_client import Gauge
from zentral.utils.prometheus import BasePrometheusMetricsView
from .models import Status


logger = logging.getLogger("zentral.core.compliance_checks.metrics_views")


class MetricsView(BasePrometheusMetricsView):
    def add_compliance_checks_gauge(self):
        g = Gauge('zentral_compliance_checks', 'Zentral compliance checks',
                  ['model'], registry=self.registry)
        query = (
            "select model, count(*) "
            "from compliance_checks_compliancecheck "
            "group by model"
        )
        with connection.cursor() as cursor:
            cursor.execute(query)
            for model, count in cursor.fetchall():
                g.labels(model=model).set(count)

    def add_machine_statuses_gauge(self):
        g = Gauge('zentral_compliance_checks_statuses_bucket', 'Zentral compliance checks statuses',
                  ['model', 'name', 'status', 'le'],
                  registry=self.registry)
        query = (
            "with machine_statuses as ("
            "  select compliance_check_id, compliance_check_version, status,"
            "  date_part('days', now() - status_time) as age"
            "  from compliance_checks_machinestatus"
            ") select "
            "cc.model, cc.name, ms.status,"
            'count(*) filter (where ms.age < 1) as "1",'
            'count(*) filter (where ms.age < 7) as "7",'
            'count(*) filter (where ms.age < 14) as "14",'
            'count(*) filter (where ms.age < 30) as "30",'
            'count(*) filter (where ms.age < 45) as "45",'
            'count(*) filter (where ms.age < 90) as "90",'
            'count(*) as "+Inf" '
            "from compliance_checks_compliancecheck as cc "
            "join machine_statuses as ms on "
            "(ms.compliance_check_id = cc.id and ms.compliance_check_version = cc.version) "
            "group by cc.model, cc.name, ms.status"
        )
        with connection.cursor() as cursor:
            cursor.execute(query)
            columns = [c.name for c in cursor.description]
            for row in cursor.fetchall():
                row_d = dict(zip(columns, row))
                for le in ("1", "7", "14", "30", "45", "90", "+Inf"):
                    g.labels(
                        model=row_d["model"],
                        name=row_d["name"],
                        status=Status(row_d["status"]).name,
                        le=le
                    ).set(
                        row_d[le]
                    )

    def populate_registry(self):
        self.add_compliance_checks_gauge()
        self.add_machine_statuses_gauge()
