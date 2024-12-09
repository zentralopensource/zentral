import logging
from django.db import connection
from prometheus_client import Gauge
from zentral.utils.prometheus import BasePrometheusMetricsView
from .models import Configuration, Rule, TargetState


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
                  ['cfg_pk', 'ruleset', 'target_type', 'policy', 'voting',
                   'users', 'machines', 'excluded_users', 'excluded_machines'],
                  registry=self.registry)
        query = (
            "select r.configuration_id cfg_pk, s.name ruleset, t.type target_type, r.policy, r.is_voting_rule,"
            "cardinality(primary_users) > 0 users,"
            "cardinality(serial_numbers) > 0 machines,"
            "cardinality(excluded_primary_users) > 0 excluded_users,"
            "cardinality(excluded_serial_numbers) > 0 excluded_machines,"
            "count(*) "
            "from santa_rule as r "
            "left join santa_ruleset as s on (r.ruleset_id = s.id) "
            "join santa_target as t on (r.target_id = t.id) "
            "group by r.configuration_id, s.name, t.type, r.policy, r.is_voting_rule,"
            "users, machines, excluded_users, excluded_machines"
        )
        with connection.cursor() as cursor:
            cursor.execute(query)
            columns = [c.name for c in cursor.description]
            for result in cursor.fetchall():
                result_d = dict(zip(columns, result))
                try:
                    policy_label = Rule.Policy(result_d["policy"]).name
                except ValueError:
                    logger.error("Unknown rule policy: %s", result_d["policy"])
                    continue
                g.labels(
                    cfg_pk=result_d["cfg_pk"],
                    ruleset=result_d["ruleset"] if result_d["ruleset"] else "_",
                    target_type=result_d["target_type"],
                    policy=policy_label,
                    voting=str(result_d["is_voting_rule"]).lower(),
                    users=str(result_d["users"]).lower(),
                    machines=str(result_d["machines"]).lower(),
                    excluded_users=str(result_d["excluded_users"]).lower(),
                    excluded_machines=str(result_d["excluded_machines"]).lower(),
                ).set(result_d["count"])

    def add_targets_gauges(self):
        totals = ("total", "blocked_total", "executed_total", "collected_total", "rules_total")
        gauges = {}
        for total in totals:
            total_for_display = " ".join(w.title() for w in total.split("_") if w != "total")
            gauges[total] = Gauge(
                f'zentral_santa_targets_{total}',
                f'Zentral Santa Targets {total_for_display}'.strip(),
                ["cfg_pk", "type", "state"],
                registry=self.registry,
            )
        query = (
            "with target_config_product as ("
            "  select t.id target_id, t.type target_type, c.id cfg_pk"
            "  from santa_target t, santa_configuration c"
            ")"
            "select tcp.target_type, tcp.cfg_pk, coalesce(ts.state, 0) state, count(*) total, "
            "coalesce(sum(tc.blocked_count), 0) as blocked_total,"
            "coalesce(sum(tc.collected_count), 0) as collected_total,"
            "coalesce(sum(tc.executed_count), 0) as executed_total,"
            "sum(case when r.id is null then 0 else 1 end) rules_total "
            "from target_config_product tcp "
            "left join santa_targetstate ts on (ts.target_id = tcp.target_id and ts.configuration_id = tcp.cfg_pk) "
            "left join santa_targetcounter tc on (tc.target_id = tcp.target_id and tc.configuration_id = tcp.cfg_pk) "
            "left join santa_rule r on (r.target_id = tcp.target_id and r.configuration_id = tcp.cfg_pk) "
            "group by tcp.target_type, tcp.cfg_pk, ts.state"
        )
        with connection.cursor() as cursor:
            cursor.execute(query)
            columns = [c.name for c in cursor.description]
            for result in cursor.fetchall():
                result_d = dict(zip(columns, result))
                for total in totals:
                    try:
                        state = TargetState.State(result_d["state"]).name
                    except ValueError:
                        logger.error("Unknown target state: %s", result_d["state"])
                        continue
                    gauges[total].labels(
                        cfg_pk=result_d["cfg_pk"],
                        type=result_d["target_type"],
                        state=state,
                    ).set(result_d[total])

    def add_votes_gauge(self):
        g = Gauge('zentral_santa_votes_total', 'Zentral Santa Votes',
                  ['cfg_pk', 'realm', 'yes', 'weight', 'target_type', 'event_target_type'], registry=self.registry)
        query = (
            "select v.configuration_id, r.name, v.was_yes_vote, v.weight, t.type, et.type, count(*) "
            "from santa_vote v "
            "join santa_ballot b on (v.ballot_id = b.id) "
            "left join realms_realmuser u on (b.realm_user_id = u.uuid) "
            "left join realms_realm r on (u.realm_id = r.uuid) "
            "join santa_target t on (b.target_id = t.id) "
            "left join santa_target et on (b.event_target_id = et.id) "
            "group by v.configuration_id, r.name, v.was_yes_vote, v.weight, t.type, et.type;"
        )
        with connection.cursor() as cursor:
            cursor.execute(query)
            for cfg_pk, realm_name, was_yes_vote, weight, target_type, event_target_type, count in cursor.fetchall():
                g.labels(
                    cfg_pk=cfg_pk,
                    realm=realm_name if realm_name else "_",
                    yes=str(was_yes_vote).lower(),
                    weight=weight,
                    target_type=target_type,
                    event_target_type=event_target_type if event_target_type else "_",
                ).set(count)

    def populate_registry(self):
        self.add_configurations_info()
        self.add_enrolled_machines_gauge()
        self.add_rules_gauge()
        self.add_targets_gauges()
        self.add_votes_gauge()
