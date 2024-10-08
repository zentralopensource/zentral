import logging
from django.db import connection
from prometheus_client import Gauge
from zentral.utils.prometheus import BasePrometheusMetricsView
from .models import Configuration, Rule


logger = logging.getLogger("zentral.contrib.santa.metrics_views")


class MetricsView(BasePrometheusMetricsView):
    @staticmethod
    def _add_mode_to_labels(mode, labels):
        if mode == Configuration.MONITOR_MODE:
            labels["mode"] = "MONITOR"
        elif mode == Configuration.LOCKDOWN_MODE:
            labels["mode"] = "LOCKDOWN"
        else:
            logger.warning("Unknown santa configuration mode: %s", mode)
            return False
        return True

    def add_configurations_info(self):
        g = Gauge('zentral_santa_configurations_info', 'Zentral Santa configuration info',
                  ['pk', 'name', 'mode'], registry=self.registry)
        query = "select id, name, client_mode from santa_configuration;"
        with connection.cursor() as cursor:
            cursor.execute(query)
            for cfg_pk, name, mode in cursor.fetchall():
                labels = {
                    "pk": cfg_pk,
                    "name": name,
                }
                if not self._add_mode_to_labels(mode, labels):
                    continue
                g.labels(**labels).set(1)

    def add_enrolled_machines_gauge(self):
        g = Gauge('zentral_santa_enrolled_machines_total', 'Zentral Santa Enrolled Machines',
                  ['cfg_pk', 'mode', 'santa_version'], registry=self.registry)
        query = (
            "select e.configuration_id, m.client_mode, m.santa_version, count(*) "
            "from santa_enrolledmachine as m "
            "join santa_enrollment as e on (m.enrollment_id = e.id) "
            "group by e.configuration_id, m.client_mode, m.santa_version"
        )
        with connection.cursor() as cursor:
            cursor.execute(query)
            for cfg_pk, mode, santa_version, count in cursor.fetchall():
                labels = {"cfg_pk": cfg_pk,
                          "santa_version": santa_version}
                if not self._add_mode_to_labels(mode, labels):
                    continue
                g.labels(**labels).set(count)

    def add_rules_gauge(self):
        g = Gauge('zentral_santa_rules_total', 'Zentral Santa Rules',
                  ['cfg_pk', 'ruleset', 'target_type', 'policy'], registry=self.registry)
        query = (
            "select r.configuration_id, s.name, t.type, r.policy, count(*) "
            "from santa_rule as r "
            "left join santa_ruleset as s on (r.ruleset_id = s.id) "
            "join santa_target as t on (r.target_id = t.id) "
            "group by r.configuration_id, s.name, t.type, r.policy"
        )
        with connection.cursor() as cursor:
            cursor.execute(query)
            for cfg_pk, ruleset, target_type, policy, count in cursor.fetchall():
                try:
                    policy_label = Rule.Policy(policy).name
                except ValueError:
                    logger.error("Unknown rule policy: %s", policy)
                    continue
                g.labels(
                    cfg_pk=cfg_pk,
                    ruleset=ruleset if ruleset else "_",
                    target_type=target_type,
                    policy=policy_label,
                ).set(count)

    def add_targets_gauges(self):
        totals = ("total", "blocked_total", "executed_total", "collected_total", "rules_total")
        gauges = {}
        for total in totals:
            total_for_display = " ".join(w.title() for w in total.split("_") if w != "total")
            gauges[total] = Gauge(
                f'zentral_santa_targets_{total}',
                f'Zentral Santa Targets {total_for_display}'.strip(),
                ["cfg_pk", "type"],
                registry=self.registry,
            )
        query = (
            "with target_config_product as ("
            "  select t.id target_id, t.type target_type, c.id cfg_pk"
            "  from santa_target t, santa_configuration c"
            ")"
            "select tcp.target_type, tcp.cfg_pk, count(*) total, "
            "coalesce(sum(tc.blocked_count), 0) as blocked_total,"
            "coalesce(sum(tc.collected_count), 0) as collected_total,"
            "coalesce(sum(tc.executed_count), 0) as executed_total,"
            "sum(case when r.id is null then 0 else 1 end) rules_total "
            "from target_config_product tcp "
            "left join santa_targetcounter tc on (tc.target_id = tcp.target_id and tc.configuration_id = tcp.cfg_pk) "
            "left join santa_rule r on (r.target_id = tcp.target_id and r.configuration_id = tcp.cfg_pk) "
            "group by tcp.target_type, tcp.cfg_pk"
        )
        with connection.cursor() as cursor:
            cursor.execute(query)
            columns = [c.name for c in cursor.description]
            for result in cursor.fetchall():
                result_d = dict(zip(columns, result))
                for total in totals:
                    gauges[total].labels(
                        cfg_pk=result_d["cfg_pk"],
                        type=result_d["target_type"]
                    ).set(result_d[total])

    def populate_registry(self):
        self.add_configurations_info()
        self.add_enrolled_machines_gauge()
        self.add_rules_gauge()
        self.add_targets_gauges()
