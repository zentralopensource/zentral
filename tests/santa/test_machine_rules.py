from django.test import TestCase
from zentral.contrib.santa.models import EnrolledMachine, MachineRule, Rule, Target

from .utils import SantaSyncClient, force_configuration, force_enrolled_machine, force_rule, new_sha256


class SantaMachineRulesTestCase(TestCase):
    """The rows of the Rules tab: the server side, the ledger, and the state of each target."""

    maxDiff = None

    # utils

    def force_client(self):
        configuration = force_configuration()
        enrolled_machine = force_enrolled_machine(configuration=configuration)
        return SantaSyncClient(enrolled_machine), configuration, enrolled_machine

    def rows(self, enrolled_machine, tags=None):
        return {row["identifier"]: row
                for row in MachineRule.objects.rows_for_machine(enrolled_machine, tags or [])}

    def states(self, enrolled_machine, tags=None):
        return {identifier: row["state"] for identifier, row in self.rows(enrolled_machine, tags).items()}

    def force_binary_rule(self, configuration, **kwargs):
        return force_rule(configuration=configuration, target_type=Target.Type.BINARY,
                          target_identifier=new_sha256(), **kwargs)

    # the states

    def test_no_rule_no_ledger(self):
        _, _, enrolled_machine = self.force_client()
        self.assertEqual(self.rows(enrolled_machine), {})

    def test_rule_not_yet_on_device(self):
        client, configuration, enrolled_machine = self.force_client()
        rule = self.force_binary_rule(configuration)
        self.assertEqual(self.states(enrolled_machine),
                         {rule.target.identifier: MachineRule.State.NOT_YET})

    def test_rule_on_device_after_a_sync(self):
        client, configuration, enrolled_machine = self.force_client()
        rule = self.force_binary_rule(configuration)
        client.sync()
        self.assertEqual(self.states(enrolled_machine),
                         {rule.target.identifier: MachineRule.State.ON_DEVICE})

    def test_rule_staged_is_not_yet_on_device(self):
        client, configuration, enrolled_machine = self.force_client()
        rule = self.force_binary_rule(configuration)
        # the download stages the rule, and santa writes its database at the end of the download:
        # the rule is not on the device until the postflight confirms it
        client.preflight()
        client.rule_download()
        self.assertEqual(self.states(enrolled_machine),
                         {rule.target.identifier: MachineRule.State.NOT_YET})

    def test_policy_change_is_not_yet_on_device(self):
        client, configuration, enrolled_machine = self.force_client()
        rule = self.force_binary_rule(configuration, policy=Rule.Policy.BLOCKLIST)
        client.sync()
        Rule.objects.filter(pk=rule.pk).update(policy=Rule.Policy.ALLOWLIST)
        row = self.rows(enrolled_machine)[rule.target.identifier]
        self.assertEqual(row["state"], MachineRule.State.NOT_YET)
        # the row carries both policies, the server one and the device one, with their version
        self.assertEqual((row["winner"]["policy"], row["winner"]["version"]),
                         (Rule.Policy.ALLOWLIST, 1))
        self.assertEqual((row["device_policy"], row["device_version"]),
                         (Rule.Policy.BLOCKLIST, 1))

    def test_rule_still_on_device(self):
        client, configuration, enrolled_machine = self.force_client()
        rule = self.force_binary_rule(configuration)
        client.sync()
        Rule.objects.filter(pk=rule.pk).delete()
        row = self.rows(enrolled_machine)[rule.target.identifier]
        self.assertEqual(row["state"], MachineRule.State.STILL)
        self.assertIsNone(row["winner"])
        self.assertEqual(row["device_policy"], Rule.Policy.BLOCKLIST)

    def test_rule_out_of_scope_is_still_on_device(self):
        client, configuration, enrolled_machine = self.force_client()
        rule = self.force_binary_rule(configuration)
        client.sync()
        # the rule is not for this machine anymore, and the next sync sends the removal
        Rule.objects.filter(pk=rule.pk).update(serial_numbers=["another-serial-number"])
        self.assertEqual(self.states(enrolled_machine),
                         {rule.target.identifier: MachineRule.State.STILL})

    def test_a_removal_staged_over_a_staged_rule_is_not_a_row(self):
        client, configuration, enrolled_machine = self.force_client()
        rule = self.force_binary_rule(configuration)
        client.preflight()
        client.rule_download()
        # the session staged the rule, then a removal over it: the client holds nothing for the
        # target, and there is nothing left to send. The ledger row is bookkeeping, not a rule
        Rule.objects.filter(pk=rule.pk).delete()
        MachineRule.objects.filter(enrolled_machine=enrolled_machine).update(staged_removal=True)
        self.assertEqual(self.rows(enrolled_machine), {})

    # the candidates

    def test_the_rule_that_decides_a_target(self):
        client, configuration, enrolled_machine = self.force_client()
        blocklist = self.force_binary_rule(configuration, policy=Rule.Policy.BLOCKLIST)
        # a second rule on the same target, for this machine only: it is narrower, and it wins
        allowlist = Rule.objects.create(configuration=configuration, target=blocklist.target,
                                        policy=Rule.Policy.ALLOWLIST,
                                        serial_numbers=[enrolled_machine.serial_number])
        row = self.rows(enrolled_machine)[blocklist.target.identifier]
        self.assertEqual(row["winner"]["rule_id"], allowlist.pk)
        self.assertEqual(row["winner"]["match_rank"], 0)
        self.assertEqual(row["rules_in_configuration"], 2)

    def test_a_rule_out_of_scope_is_not_a_candidate(self):
        client, configuration, enrolled_machine = self.force_client()
        rule = self.force_binary_rule(configuration, excluded_serial_numbers=[enrolled_machine.serial_number])
        self.assertEqual(self.rows(enrolled_machine), {})
        self.assertTrue(Rule.objects.filter(pk=rule.pk).exists())

    def test_the_rules_are_ordered_like_the_client_reads_them(self):
        client, configuration, enrolled_machine = self.force_client()
        for target_type in (Target.Type.TEAM_ID, Target.Type.CDHASH, Target.Type.SIGNING_ID):
            force_rule(configuration=configuration, target_type=target_type)
        rows = MachineRule.objects.rows_for_machine(enrolled_machine, [])
        self.assertEqual([row["target_type"] for row in rows],
                         [Target.Type.CDHASH, Target.Type.SIGNING_ID, Target.Type.TEAM_ID])

    # the trust test

    def assert_trust_test(self, enrolled_machine, client):
        """The rows to send are exactly what the next download sends."""
        to_send = {identifier for identifier, state in self.states(enrolled_machine).items()
                   if state in (MachineRule.State.NOT_YET, MachineRule.State.STILL)}
        client.preflight()
        rules = client.rule_download()
        self.assertEqual(to_send, {rule.get("identifier") or rule.get("sha256") for rule in rules})

    def test_trust_test_new_rules(self):
        client, configuration, enrolled_machine = self.force_client()
        for _ in range(3):
            self.force_binary_rule(configuration)
        self.assert_trust_test(enrolled_machine, client)

    def test_trust_test_nothing_to_send(self):
        client, configuration, enrolled_machine = self.force_client()
        self.force_binary_rule(configuration)
        client.sync()
        self.assert_trust_test(enrolled_machine, client)

    def test_trust_test_a_removal_and_a_change(self):
        client, configuration, enrolled_machine = self.force_client()
        removed = self.force_binary_rule(configuration)
        changed = self.force_binary_rule(configuration)
        self.force_binary_rule(configuration)
        client.sync()
        Rule.objects.filter(pk=removed.pk).delete()
        Rule.objects.filter(pk=changed.pk).update(policy=Rule.Policy.ALLOWLIST)
        self.assert_trust_test(enrolled_machine, client)

    # a CEL rule the client cannot evaluate

    def test_cel_rule_skipped_by_an_old_client(self):
        client, configuration, enrolled_machine = self.force_client()
        EnrolledMachine.objects.filter(pk=enrolled_machine.pk).update(santa_version="2024.5")
        enrolled_machine.refresh_from_db()
        rule = self.force_binary_rule(configuration, policy=Rule.Policy.CEL, cel_expr="true")
        row = self.rows(enrolled_machine)[rule.target.identifier]
        self.assertEqual(row["state"], MachineRule.State.SKIPPED)
        self.assertIsNone(row["winner"])
        self.assertEqual([c["rule_id"] for c in row["skipped"]], [rule.pk])

    def test_cel_rule_sent_to_a_recent_client(self):
        client, configuration, enrolled_machine = self.force_client()
        EnrolledMachine.objects.filter(pk=enrolled_machine.pk).update(santa_version="2026.7")
        enrolled_machine.refresh_from_db()
        rule = self.force_binary_rule(configuration, policy=Rule.Policy.CEL, cel_expr="true")
        row = self.rows(enrolled_machine)[rule.target.identifier]
        self.assertEqual(row["state"], MachineRule.State.NOT_YET)
        self.assertEqual(row["winner"]["rule_id"], rule.pk)
        self.assertEqual(row["skipped"], [])

    def test_a_skipped_rule_does_not_decide(self):
        client, configuration, enrolled_machine = self.force_client()
        EnrolledMachine.objects.filter(pk=enrolled_machine.pk).update(santa_version="2024.5")
        enrolled_machine.refresh_from_db()
        # the CEL rule is narrower, but the client cannot evaluate it: the fleet rule decides,
        # exactly as the download picks it
        blocklist = self.force_binary_rule(configuration, policy=Rule.Policy.BLOCKLIST)
        cel = Rule.objects.create(configuration=configuration, target=blocklist.target,
                                  policy=Rule.Policy.CEL, cel_expr="true",
                                  serial_numbers=[enrolled_machine.serial_number])
        row = self.rows(enrolled_machine)[blocklist.target.identifier]
        self.assertEqual(row["winner"]["rule_id"], blocklist.pk)
        self.assertEqual([c["rule_id"] for c in row["skipped"]], [cel.pk])
        self.assertEqual(row["state"], MachineRule.State.NOT_YET)

    def test_trust_test_with_a_skipped_rule(self):
        client, configuration, enrolled_machine = self.force_client()
        EnrolledMachine.objects.filter(pk=enrolled_machine.pk).update(santa_version="2024.5")
        enrolled_machine.refresh_from_db()
        self.force_binary_rule(configuration, policy=Rule.Policy.CEL, cel_expr="true")
        self.force_binary_rule(configuration)
        # a skipped rule sends nothing, so it is not in the trust test
        self.assert_trust_test(enrolled_machine, client)

    # the rules of the configuration for a target

    def test_rules_in_configuration(self):
        client, configuration, enrolled_machine = self.force_client()
        rule = self.force_binary_rule(configuration)
        # a second rule for the target, out of scope for this machine: it is not a candidate, and
        # it is one of the rules of the configuration for the target
        Rule.objects.create(configuration=configuration, target=rule.target,
                            policy=Rule.Policy.ALLOWLIST,
                            serial_numbers=["another-serial-number"])
        row = self.rows(enrolled_machine)[rule.target.identifier]
        self.assertEqual(row["rules_in_configuration"], 2)
        self.assertEqual(row["winner"]["rule_id"], rule.pk)
