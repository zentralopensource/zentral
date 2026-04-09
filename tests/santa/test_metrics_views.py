from unittest.mock import Mock, call, patch

from django.test import TestCase
from django.urls import reverse
from prometheus_client.parser import text_string_to_metric_families

from zentral.conf import settings
from zentral.contrib.santa.models import Rule, Target, TargetState

from .utils import (
    force_ballot,
    force_configuration,
    force_enrolled_machine,
    force_realm_user,
    force_rule,
    force_target,
    force_target_state,
)


class SantaMetricsViewsTestCase(TestCase):
    # utility methods

    def _make_authenticated_request(self):
        return self.client.get(reverse("santa_metrics:all"),
                               HTTP_AUTHORIZATION=f'Bearer {settings["api"]["metrics_bearer_token"]}')

    # metrics

    def test_metrics_permission_denied(self):
        response = self.client.get(reverse("santa_metrics:all"))
        self.assertEqual(response.status_code, 403)

    def test_metrics_permission_ok(self):
        response = self._make_authenticated_request()
        self.assertEqual(response.status_code, 200)

    def test_configurations(self):
        config_m = force_configuration(lockdown=False)
        config_l = force_configuration(lockdown=True)
        response = self._make_authenticated_request()
        for family in text_string_to_metric_families(response.content.decode("utf-8")):
            if family.name != "zentral_santa_configurations_info":
                continue
            else:
                self.assertEqual(len(family.samples), 2)
                for sample in family.samples:
                    self.assertEqual(sample.value, 1)
                    if int(sample.labels["pk"]) == config_m.pk:
                        self.assertEqual(sample.labels["mode"], "MONITOR")
                        self.assertEqual(sample.labels["name"], config_m.name)
                    elif int(sample.labels["pk"]) == config_l.pk:
                        self.assertEqual(sample.labels["mode"], "LOCKDOWN")
                        self.assertEqual(sample.labels["name"], config_l.name)
                    else:
                        raise AssertionError("Unknown config")
                break
        else:
            raise AssertionError("could not find expected metric family")
        self.assertEqual(response.status_code, 200)

    @patch("zentral.contrib.santa.metrics_views.connection")
    @patch("zentral.contrib.santa.metrics_views.logger.warning")
    def test_configurations_info_unknown_mode(self, warning, connection):
        mocked_fetchall = connection.cursor.return_value.__enter__.return_value.fetchall
        mocked_fetchall.side_effect = [
            [(1, "yolo", 42)],  # 1st call with bad mode
            [],  # 2nd call for the enrolled machines gauge
            [],  # 3rd call for the rules gauge
            [],  # 4th call for the target states gauge
            [],  # 5th call for the votes gauge
        ]
        response = self._make_authenticated_request()
        family_count = 0
        sample_count = 0
        for family in text_string_to_metric_families(response.content.decode("utf-8")):
            if family.name != "zentral_santa_configurations_info":
                continue
            family_count += 1
            sample_count += len(family.samples)
        self.assertEqual(family_count, 1)
        self.assertEqual(sample_count, 0)
        warning.assert_called_once_with("Unknown santa configuration mode: %s", 42)
        self.assertEqual(mocked_fetchall.mock_calls, [call() for _ in range(5)])

    def test_enrolled_machines(self):
        em_m = force_enrolled_machine(lockdown=False, santa_version="2024.5")
        em_l = force_enrolled_machine(lockdown=True, santa_version="2024.6")
        response = self._make_authenticated_request()
        for family in text_string_to_metric_families(response.content.decode("utf-8")):
            if family.name != "zentral_santa_enrolled_machines_total":
                continue
            self.assertEqual(len(family.samples), 2)
            for sample in family.samples:
                self.assertEqual(sample.value, 1)
                cfg_pk = int(sample.labels["cfg_pk"])
                if cfg_pk == em_m.enrollment.configuration.pk:
                    self.assertEqual(sample.labels["mode"], "MONITOR")
                    self.assertEqual(sample.labels["santa_version"], "2024.5")
                elif cfg_pk == em_l.enrollment.configuration.pk:
                    self.assertEqual(sample.labels["mode"], "LOCKDOWN")
                    self.assertEqual(sample.labels["santa_version"], "2024.6")
                else:
                    raise AssertionError("Unknown enrolled machine")
            break
        else:
            raise AssertionError("could not find expected metric family")
        self.assertEqual(response.status_code, 200)

    @patch("zentral.contrib.santa.metrics_views.connection")
    @patch("zentral.contrib.santa.metrics_views.logger.warning")
    def test_enrolled_machines_unknown_mode(self, warning, connection):
        mocked_fetchall = connection.cursor.return_value.__enter__.return_value.fetchall
        mocked_fetchall.side_effect = [
            [],  # 1st call for the configurations info gauge
            [(1, 42, "2024.5", 1)],  # 2nd call for the enrolled machines gauge
            [],  # 3rd call for the rules gauge
            [],  # 4th call for the target states gauge
            [],  # 5th call for the votes gauge
        ]
        response = self._make_authenticated_request()
        family_count = 0
        sample_count = 0
        for family in text_string_to_metric_families(response.content.decode("utf-8")):
            if family.name != "zentral_santa_enrolled_machines_total":
                continue
            family_count += 1
            sample_count += len(family.samples)
        self.assertEqual(family_count, 1)
        self.assertEqual(sample_count, 0)
        warning.assert_called_once_with("Unknown santa configuration mode: %s", 42)
        self.assertEqual(mocked_fetchall.mock_calls, [call() for _ in range(5)])

    def test_rules(self):
        rules = {}
        for target_type, policy, is_voting_rule, pus, sns, epus, esns in (
            (Target.Type.BINARY, Rule.Policy.ALLOWLIST, False, [], [], [], []),
            (Target.Type.BUNDLE, Rule.Policy.BLOCKLIST, False, ["1"], [], [], []),
            (Target.Type.CDHASH, Rule.Policy.ALLOWLIST_COMPILER, False, [], ["2"], [], []),
            (Target.Type.CERTIFICATE, Rule.Policy.SILENT_BLOCKLIST, False, [], [], ["3"], []),
            (Target.Type.TEAM_ID, Rule.Policy.ALLOWLIST, True, [], [], [], ["4"]),
            (Target.Type.SIGNING_ID, Rule.Policy.BLOCKLIST, False, [], [], [], []),
        ):
            rule = force_rule(target_type=target_type, policy=policy,
                              primary_users=pus,
                              serial_numbers=sns,
                              excluded_primary_users=epus,
                              excluded_serial_numbers=esns)
            rules[str(rule.configuration.pk)] = rule
        response = self._make_authenticated_request()
        for family in text_string_to_metric_families(response.content.decode("utf-8")):
            if family.name != "zentral_santa_rules_total":
                continue
            self.assertEqual(len(family.samples), 6)
            for sample in family.samples:
                self.assertEqual(sample.value, 1)
                self.assertEqual(sample.labels["ruleset"], "_")
                rule = rules[sample.labels["cfg_pk"]]
                self.assertEqual(sample.labels["policy"], rule.policy.name)
                self.assertEqual(sample.labels["target_type"], rule.target.type)
                self.assertEqual(sample.labels["voting"], str(rule.is_voting_rule).lower())
                self.assertEqual(sample.labels["users"],
                                 str(len(rule.primary_users) > 0).lower())
                self.assertEqual(sample.labels["machines"],
                                 str(len(rule.serial_numbers) > 0).lower())
                self.assertEqual(sample.labels["excluded_users"],
                                 str(len(rule.excluded_primary_users) > 0).lower())
                self.assertEqual(sample.labels["excluded_machines"],
                                 str(len(rule.excluded_serial_numbers) > 0).lower())
            break
        else:
            raise AssertionError("could not find expected metric family")
        self.assertEqual(response.status_code, 200)

    @patch("zentral.contrib.santa.metrics_views.connection")
    @patch("zentral.contrib.santa.metrics_views.logger.error")
    def test_rules_unknown_policy(self, warning, connection):
        mocked_cursor = connection.cursor.return_value.__enter__.return_value
        mocked_cursor.description = []
        for name in (
            "cfg_pk", "ruleset", "target_type", "policy", "is_voting_rule",
            "users", "machines", "excluded_users", "excluded_machines", "count",
        ):
            col = Mock()
            col.name = name
            mocked_cursor.description.append(col)
        mocked_cursor.fetchall.side_effect = [
            [],  # 1st call for the configurations info
            [],  # 2nd call for the enrolled machines gauge
            [(1, None, "BUNDLE", 42, False, True, False, False, False, 1)],  # 3rd call with unknown policy
            [],  # 4th call for the target states gauge
            [],  # 5th call for the votes gauge
        ]
        response = self._make_authenticated_request()
        family_count = 0
        sample_count = 0
        for family in text_string_to_metric_families(response.content.decode("utf-8")):
            if family.name != "zentral_santa_rules_total":
                continue
            family_count += 1
            sample_count += len(family.samples)
        self.assertEqual(family_count, 1)
        self.assertEqual(sample_count, 0)
        warning.assert_called_once_with("Unknown rule policy: %s", 42)
        self.assertEqual(mocked_cursor.fetchall.mock_calls, [call() for _ in range(5)])

    def test_target_states(self):
        configuration = force_configuration()
        target_states = {}
        for target_type, state, flagged in (
            (Target.Type.BINARY, TargetState.State.GLOBALLY_ALLOWLISTED, False),
            (Target.Type.CERTIFICATE, TargetState.State.BANNED, False),
            (Target.Type.SIGNING_ID, TargetState.State.SUSPECT, True),
        ):
            force_target_state(
                configuration=configuration,
                target=force_target(target_type),
                state=state,
                flagged=flagged
            )
            target_states[(target_type, state.value, flagged)] = 1
        response = self._make_authenticated_request()
        for family in text_string_to_metric_families(response.content.decode("utf-8")):
            if family.name != "zentral_santa_target_states":
                continue
            self.assertEqual(len(family.samples), 3)
            for sample in family.samples:
                self.assertEqual(int(sample.labels["cfg_pk"]), configuration.pk)
                key = (
                    sample.labels["target_type"],
                    int(sample.labels["target_state"]),
                    sample.labels["target_flagged"] == "true",
                )
                self.assertEqual(sample.value, target_states[key])
            break
        else:
            raise AssertionError("could not find zentral_santa_target_states")

    def test_votes(self):
        target = force_target()
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        force_ballot(target, realm_user, [(configuration, True, 1)])
        response = self._make_authenticated_request()
        self.assertEqual(response.status_code, 200)
        for family in text_string_to_metric_families(response.content.decode("utf-8")):
            if family.name != "zentral_santa_votes_total":
                continue
            self.assertEqual(len(family.samples), 1)
            for sample in family.samples:
                self.assertEqual(sample.value, 1)
                self.assertEqual(sample.labels["cfg_pk"], str(configuration.pk))
                self.assertEqual(sample.labels["event_target_type"], "_")
                self.assertEqual(sample.labels["realm"], realm.name)
                self.assertEqual(sample.labels["target_type"], target.type)
                self.assertEqual(sample.labels["weight"], "1")
                self.assertEqual(sample.labels["yes"], "true")
            break
        else:
            raise AssertionError("could not find expected metric family")
