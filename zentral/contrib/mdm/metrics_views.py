import logging
from django.db import connection
from prometheus_client import Counter
from zentral.utils.prometheus import BasePrometheusMetricsView


logger = logging.getLogger("zentral.core.mdm.metrics_views")


class MetricsView(BasePrometheusMetricsView):
    def populate_enrollment_sessions(self):
        esc = Counter(
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
                esc.labels(
                    type=type,
                    status=status,
                    realm=realm or "_",
                ).inc(count)

    def populate_commands(self):
        cc = Counter(
            'zentral_mdm_commands', 'Zentral MDM commands',
            ['channel', 'name', 'status', 'artifact', 'version'],
            registry=self.registry
        )
        with connection.cursor() as cursor:
            cursor.execute(
                "with agg_cmds as ("
                "  select 'device' channel, name, status, artifact_version_id, count(*) count"
                "  from mdm_devicecommand"
                "  group by channel, name, status, artifact_version_id"
                "  union"
                "  select 'user' channel, name, status, artifact_version_id, count(*) count"
                "  from mdm_usercommand"
                "  group by channel, name, status, artifact_version_id"
                ") "
                "select acs.channel, acs.name, acs.status, a.name, av.version, acs.count "
                "from agg_cmds acs "
                "left join mdm_artifactversion av on (acs.artifact_version_id = av.id) "
                "left join mdm_artifact a on (a.id = av.artifact_id)"
            )
            for channel, name, status, artifact, version, count in cursor.fetchall():
                cc.labels(
                    channel=channel,
                    name=name,
                    status=status or "_",
                    artifact=artifact or "_",
                    version=str(version) if version is not None else "_"
                ).inc(count)

    def populate_registry(self):
        self.populate_enrollment_sessions()
        self.populate_commands()
