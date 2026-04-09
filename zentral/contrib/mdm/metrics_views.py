import logging

from django.db import connection
from prometheus_client import Counter, Gauge

from zentral.utils.prometheus import BasePrometheusMetricsView

from .models import Channel

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

    def populate_enrolled_devices(self):
        edg = Gauge(
            'zentral_mdm_devices', 'Zentral MDM devices',
            ['blueprint', 'platform', 'supervised', 'blocked', 'le'],
            registry=self.registry,
        )
        with connection.cursor() as cursor:
            cursor.execute(
                "with devices as ("
                "  select b.name blueprint, d.platform, d.supervised,"
                "  case when d.blocked_at is null then FALSE else TRUE end blocked,"
                "  case when last_seen_at is not null"
                "  then date_part('days', now() - last_seen_at)"
                "  else null end age"
                "  from mdm_enrolleddevice d"
                "  left join mdm_blueprint b on (d.blueprint_id = b.id)"
                ") "
                "select blueprint, platform, supervised, blocked,"
                'count(*) filter (where age is not null and age < 1) "1",'
                'count(*) filter (where age is not null and age < 7) "7",'
                'count(*) filter (where age is not null and age < 14) "14",'
                'count(*) filter (where age is not null and age < 30) "30",'
                'count(*) filter (where age is not null and age < 45) "45",'
                'count(*) filter (where age is not null and age < 90) "90",'
                'count(*) as "+Inf" '
                'from devices '
                'group by blueprint, platform, supervised, blocked'
            )
            columns = [c.name for c in cursor.description]
            for row in cursor.fetchall():
                row_d = dict(zip(columns, row))
                supervised = row_d.pop("supervised")
                default_labels = {
                    "blueprint": row_d.pop("blueprint") or "_",
                    "platform": row_d.pop("platform") or "_",
                    "supervised": "_" if supervised is None else str(supervised).lower(),
                    "blocked": str(row_d.pop("blocked")).lower(),
                }
                for le, val in row_d.items():
                    edg.labels(le=le, **default_labels).set(val)

    def populate_installed_artifact_version(self):
        iavg = Gauge(
            "zentral_mdm_target_artifacts",
            "Zentral MDM target artifacts",
            ["name", "type", "channel", "status", "version"],
            registry=self.registry,
        )
        with connection.cursor() as cursor:
            cursor.execute(
                "select a.name, a.type, a.channel, av.version,"
                " count(ua.id) as users, count(da.id) as devices, ua.status, da.status"
                " from mdm_artifact a"
                " join mdm_artifactversion av on (av.artifact_id = a.id)"
                " left join mdm_deviceartifact da on (da.artifact_version_id = av.id)"
                " left join mdm_userartifact ua on (ua.artifact_version_id = av.id)"
                " group by a.name, a.type, a.channel, av.version, ua.status, da.status"
            )
            for (
                artifact_name,
                artifact_type,
                channel,
                version,
                users,
                devices,
                user_status,
                device_status,
            ) in cursor.fetchall():
                if channel == Channel.USER:
                    count = users
                    status = user_status
                else:
                    count = devices
                    status = device_status
                iavg.labels(
                    name=artifact_name,
                    type=artifact_type,
                    channel=channel,
                    status=status,
                    version=str(version),
                ).set(count)

    def populate_registry(self):
        self.populate_enrollment_sessions()
        self.populate_commands()
        self.populate_enrolled_devices()
        self.populate_installed_artifact_version()
