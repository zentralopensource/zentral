import logging
from django.db import connection
from prometheus_client import Gauge
from zentral.utils.prometheus import BasePrometheusMetricsView


logger = logging.getLogger("zentral.realms.metrics_views")


class MetricsView(BasePrometheusMetricsView):
    def populate_realms(self):
        rg = Gauge(
            'zentral_realms', 'Zentral realms',
            ['backend', 'enabled_for_login', 'user_portal', 'scim_enabled'],
            registry=self.registry
        )
        with connection.cursor() as cursor:
            cursor.execute(
                "select backend, enabled_for_login, user_portal, scim_enabled, count(*) "
                "from realms_realm "
                "group by backend, enabled_for_login, user_portal, scim_enabled"
            )
            for backend, enabled_for_login, user_portal, scim_enabled, count in cursor.fetchall():
                rg.labels(
                    backend=backend,
                    enabled_for_login=str(enabled_for_login).lower(),
                    user_portal=str(user_portal).lower(),
                    scim_enabled=str(scim_enabled).lower(),
                ).set(count)

    def populate_realm_groups(self):
        rgg = Gauge(
            'zentral_realm_groups', 'Zentral realm groups',
            ['realm', 'scim_managed'],
            registry=self.registry
        )
        with connection.cursor() as cursor:
            cursor.execute(
                "select r.name, rg.scim_managed, count(*) "
                "from realms_realmgroup rg "
                "join realms_realm r on r.uuid = rg.realm_id "
                "group by r.name, rg.scim_managed"
            )
            for realm, scim_managed, count in cursor.fetchall():
                rgg.labels(
                    realm=realm,
                    scim_managed=str(scim_managed).lower(),
                ).set(count)

    def populate_realm_users(self):
        rug = Gauge(
            'zentral_realm_users', 'Zentral realm users',
            ['realm', 'scim_managed', 'scim_active'],
            registry=self.registry
        )
        with connection.cursor() as cursor:
            cursor.execute(
                "select r.name,"
                "case when ru.scim_external_id is not null then TRUE else FALSE end,"
                "ru.scim_active,"
                "count(*) "
                "from realms_realmuser ru "
                "join realms_realm r on r.uuid = ru.realm_id "
                "group by r.name, 2, ru.scim_active"
            )
            for realm, scim_managed, scim_active, count in cursor.fetchall():
                rug.labels(
                    realm=realm,
                    scim_managed=str(scim_managed).lower(),
                    scim_active=str(scim_active).lower(),
                ).set(count)

    def populate_realm_group_members(self):
        rgmg = Gauge(
            'zentral_realm_group_members', 'Zentral realm group members',
            ['realm', 'realm_group', 'scim_managed'],
            registry=self.registry
        )
        with connection.cursor() as cursor:
            cursor.execute(
                "select r.name, rg.display_name, rg.scim_managed,"
                "(select count(*) from realms_realmusergroupmembership where group_id = rg.uuid) "
                "from realms_realmgroup rg "
                "join realms_realm r on r.uuid = rg.realm_id"
            )
            for realm, realm_group, scim_managed, count in cursor.fetchall():
                rgmg.labels(
                    realm=realm,
                    realm_group=realm_group,
                    scim_managed=str(scim_managed).lower(),
                ).set(count)

    def populate_registry(self):
        self.populate_realms()
        self.populate_realm_groups()
        self.populate_realm_users()
        self.populate_realm_group_members()
