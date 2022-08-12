import logging
from django.db import connection
from prometheus_client import Gauge
from zentral.utils.prometheus import BasePrometheusMetricsView
from .models import Configuration, Rule, Target


logger = logging.getLogger("zentral.contrib.santa.metrics_views")


class MetricsView(BasePrometheusMetricsView):
    @staticmethod
    def _add_mode_to_labels(mode, labels):
        if mode == Configuration.MONITOR_MODE:
            labels["mode"] = "monitor"
        elif mode == Configuration.LOCKDOWN_MODE:
            labels["mode"] = "lockdown"
        else:
            logger.warning("Unknown santa configuration mode: %s", mode)
            return False
        return True

    def add_configurations_gauge(self):
        g = Gauge('zentral_santa_configurations', 'Zentral Santa Configurations',
                  ['mode'], registry=self.registry)
        query = (
            "select client_mode, count(*) "
            "from santa_configuration "
            "group by client_mode"
        )
        cursor = connection.cursor()
        cursor.execute(query)
        for mode, count in cursor.fetchall():
            labels = {}
            if not self._add_mode_to_labels(mode, labels):
                continue
            g.labels(**labels).set(count)

    def add_enrolled_machines_gauge(self):
        g = Gauge('zentral_santa_enrolled_machines', 'Zentral Santa Enrolled Machines',
                  ['configuration', 'mode', 'santa_version'], registry=self.registry)
        query = (
            "select c.name, m.client_mode, m.santa_version, count(*) "
            "from santa_enrolledmachine as m "
            "join santa_enrollment as e on (m.enrollment_id = e.id) "
            "join santa_configuration as c on (e.configuration_id = c.id) "
            "group by c.name, m.client_mode, m.santa_version"
        )
        cursor = connection.cursor()
        cursor.execute(query)
        for configuration, mode, santa_version, count in cursor.fetchall():
            labels = {"configuration": configuration,
                      "santa_version": santa_version}
            if not self._add_mode_to_labels(mode, labels):
                continue
            g.labels(**labels).set(count)

    def add_rules_gauge(self):
        g = Gauge('zentral_santa_rules', 'Zentral Santa Rules',
                  ['configuration', 'ruleset', 'target_type', 'policy'], registry=self.registry)
        query = (
            "select c.name, s.name, t.type, r.policy, count(*) "
            "from santa_rule as r "
            "join santa_configuration as c on (r.configuration_id = c.id) "
            "left join santa_ruleset as s on (r.ruleset_id = s.id) "
            "join santa_target as t on (r.target_id = t.id) "
            "group by c.name, s.name, t.type, r.policy"
        )
        cursor = connection.cursor()
        cursor.execute(query)
        for configuration, ruleset, target_type, policy, count in cursor.fetchall():
            labels = {"configuration": configuration,
                      "ruleset": ruleset if ruleset else "_"}
            # target type
            if target_type == Target.BINARY:
                labels["target_type"] = "binary"
            elif target_type == Target.BUNDLE:
                labels["target_type"] = "bundle"
            elif target_type == Target.CERTIFICATE:
                labels["target_type"] = "certificate"
            elif target_type == Target.TEAM_ID:
                labels["target_type"] = "teamid"
            else:
                logging.warning("Unknown target type: %s", target_type)
                continue
            # policy
            if policy == Rule.ALLOWLIST:
                labels["policy"] = "allowlist"
            elif policy == Rule.BLOCKLIST:
                labels["policy"] = "blocklist"
            elif policy == Rule.SILENT_BLOCKLIST:
                labels["policy"] = "silent blocklist"
            elif policy == Rule.ALLOWLIST_COMPILER:
                labels["policy"] = "allowlist compiler"
            else:
                logging.warning("Unknown rule policy: %s", policy)
                continue
            g.labels(**labels).set(count)

    def populate_registry(self):
        self.add_configurations_gauge()
        self.add_enrolled_machines_gauge()
        self.add_rules_gauge()
