from django.test import SimpleTestCase
from zentral.contrib.santa.models import Rule, Target


class SantaRulePolicyAvailableTestCase(SimpleTestCase):
    def rule(self, policy, is_voting_rule=False):
        return Rule(policy=policy, is_voting_rule=is_voting_rule)

    def test_a_free_binary_takes_every_rule_policy_in_the_form_order(self):
        self.assertEqual(Rule.Policy.available(Target.Type.BINARY, []),
                         [Rule.Policy.ALLOWLIST, Rule.Policy.BLOCKLIST, Rule.Policy.SILENT_BLOCKLIST,
                          Rule.Policy.ALLOWLIST_COMPILER, Rule.Policy.CEL])

    def test_a_certificate_and_a_team_id_never_take_the_compiler_policy(self):
        for target_type in (Target.Type.CERTIFICATE, Target.Type.TEAM_ID):
            self.assertNotIn(Rule.Policy.ALLOWLIST_COMPILER, Rule.Policy.available(target_type, []))

    def test_a_taken_policy_is_out(self):
        rules = [self.rule(Rule.Policy.BLOCKLIST), self.rule(Rule.Policy.CEL)]
        self.assertEqual(Rule.Policy.available(Target.Type.TEAM_ID, rules),
                         [Rule.Policy.ALLOWLIST, Rule.Policy.SILENT_BLOCKLIST])

    def test_a_voting_rule_takes_the_whole_target(self):
        self.assertEqual(Rule.Policy.available(Target.Type.BINARY, [self.rule(Rule.Policy.ALLOWLIST, True)]), [])

    def test_every_policy_taken(self):
        rules = [self.rule(policy) for policy in Rule.Policy.available(Target.Type.SIGNING_ID, [])]
        self.assertEqual(Rule.Policy.available(Target.Type.SIGNING_ID, rules), [])
