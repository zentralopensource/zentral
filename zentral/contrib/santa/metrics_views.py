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

    def add_sync_states_gauge(self):
        g = Gauge('zentral_santa_enrolled_machines_sync_total', 'Zentral Santa Enrolled Machines Sync States',
                  ['cfg_pk', 'state'], registry=self.registry)
        query = (
            "select e.configuration_id, m.last_sync_ok, count(*) "
            "from santa_enrolledmachine as m "
            "join santa_enrollment as e on (m.enrollment_id = e.id) "
            "group by e.configuration_id, m.last_sync_ok"
        )
        with connection.cursor() as cursor:
            cursor.execute(query)
            for cfg_pk, last_sync_ok, count in cursor.fetchall():
                if last_sync_ok is None:
                    # no preflight since the machine enrolled, or a clean session was lost
                    state = "unknown"
                elif last_sync_ok:
                    state = "ok"
                else:
                    state = "mismatch"
                g.labels(cfg_pk=cfg_pk, state=state).set(count)

    def add_active_machines_buckets(self):
        query = (
            # last_postflight_at, not updated_at: the latter is auto_now, so a machine that
            # preflights forever without ever confirming a sync would stay in the youngest bucket.
            # Such a machine has a null age and lands in +Inf alone, which is correct - it has
            # never completed a sync.
            "with active_machines as ("
            "  select e.configuration_id as cfg_pk,"
            "  date_part('days', now() - m.last_postflight_at) as age"
            "  from santa_enrolledmachine as m"
            "  join santa_enrollment as e on (m.enrollment_id = e.id)"
            ") select cfg_pk,"
            'count(*) filter (where age < 1) as "1",'
            'count(*) filter (where age < 7) as "7",'
            'count(*) filter (where age < 14) as "14",'
            'count(*) filter (where age < 30) as "30",'
            'count(*) filter (where age < 45) as "45",'
            'count(*) filter (where age < 90) as "90",'
            'count(*) as "+Inf" '
            "from active_machines group by cfg_pk"
        )
        g = Gauge('zentral_santa_active_machines_bucket', 'Zentral Santa Active Machines',
                  ['cfg_pk', 'le'], registry=self.registry)
        with connection.cursor() as cursor:
            cursor.execute(query)
            columns = [c.name for c in cursor.description]
            for row in cursor.fetchall():
                row_d = dict(zip(columns, row))
                for le in ("1", "7", "14", "30", "45", "90", "+Inf"):
                    g.labels(cfg_pk=row_d["cfg_pk"], le=le).set(row_d[le])

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

    def add_target_states_gauge(self):
        g = Gauge(
            "zentral_santa_target_states",
            "Zentral Santa Target States",
            ["cfg_pk", "target_type", "target_state", "target_flagged"],
            registry=self.registry,
        )
        query = (
            "select ts.configuration_id cfg_pk, t.type target_type, ts.state, ts.flagged, count(*) total"
            " from santa_targetstate ts"
            " join santa_target t on (t.id = ts.target_id)"
            " group by t.type, ts.configuration_id, ts.state, ts.flagged"
        )
        with connection.cursor() as cursor:
            cursor.execute(query)
            for (
                cfg_pk,
                target_type,
                target_state,
                target_flagged,
                count,
            ) in cursor.fetchall():
                g.labels(
                    cfg_pk=cfg_pk,
                    target_type=target_type,
                    target_state=target_state,
                    target_flagged=str(target_flagged).lower(),
                ).set(count)

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
        self.add_sync_states_gauge()
        self.add_active_machines_buckets()
        self.add_rules_gauge()
        self.add_target_states_gauge()
        self.add_votes_gauge()
