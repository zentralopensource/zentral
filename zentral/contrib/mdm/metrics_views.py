import logging
from django.db import connection
from prometheus_client import Counter
from zentral.utils.prometheus import BasePrometheusMetricsView


logger = logging.getLogger("zentral.core.mdm.metrics_views")


class MetricsView(BasePrometheusMetricsView):
    def populate_enrollment_sessions(self):
        isg = Counter(
            'zentral_mdm_enrollment_sessions', 'Zentral MDM enrollment sessions',
            ['type', 'status', 'realm'],
            registry=self.registry
        )
        with connection.cursor() as cursor:
            cursor.execute(
                "with all_es as ("
                "  select 'DEP' type, status, realm_user_id from mdm_depenrollmentsession"
                "  union"
                "  select 'OTA' type, status, realm_user_id from mdm_otaenrollmentsession"
                "  union"
                "  select 'RE' type, status, realm_user_id from mdm_reenrollmentsession"
                "  union"
                "  select 'USER' type, status, realm_user_id from mdm_userenrollmentsession"
                ") select aes.type, aes.status, r.name, count(*) "
                "from all_es aes "
                "left join realms_realmuser u on (u.uuid = aes.realm_user_id) "
                "left join realms_realm r on (r.uuid = u.realm_id) "
                "group by aes.type, aes.status, r.name"
            )
            for type, status, realm, count in cursor.fetchall():
                isg.labels(
                    type=type,
                    status=status,
                    realm=realm or "_",
                ).inc(count)

    def populate_registry(self):
        self.populate_enrollment_sessions()
