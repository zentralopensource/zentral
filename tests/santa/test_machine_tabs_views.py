from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.inventory.models import Tag
from zentral.contrib.santa.models import (EnrolledMachine, MachineRule, Rule, ScopedPathRegex,
                                          Target)

from .utils import SantaSyncClient, force_configuration, force_enrolled_machine, force_rule, new_sha256


class SantaMachineTabsViewsTestCase(TestCase, LoginCase):
    """The Rules and the Path regexes tabs of a machine page."""

    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "santa"

    # utils

    def set_policy_for_actions(self, *actions):
        serialized = ", ".join(f'Santa::Action::"{action}"' for action in actions)
        Policy.objects.update_or_create(
            name="Santa tests",
            defaults={"source": ("permit ("
                                 f' principal in Role::"{self.group.pk}",'
                                 f" action in [{serialized}],"
                                 "  resource"
                                 ");\n")},
        )

    def login_with_view_enrolled_machine(self, *legacy_perms, extra_actions=()):
        self.login("santa.view_configuration", *legacy_perms)
        self.set_policy_for_actions("viewEnrolledMachine", *extra_actions)

    def rules_url(self, enrolled_machine):
        return reverse("santa:machine_rules", args=(enrolled_machine.get_urlsafe_serial_number(),))

    def path_regexes_url(self, enrolled_machine):
        return reverse("santa:machine_path_regexes", args=(enrolled_machine.get_urlsafe_serial_number(),))

    def force_machine(self):
        configuration = force_configuration()
        return force_enrolled_machine(configuration=configuration), configuration

    def force_binary_rule(self, configuration, **kwargs):
        return force_rule(configuration=configuration, target_type=Target.Type.BINARY,
                          target_identifier=new_sha256(), **kwargs)

    def force_path_regex(self, configuration, regex, block=True, name=None, tags=None,
                         excluded_tags=None, **kwargs):
        entry = ScopedPathRegex.objects.create(
            configuration=configuration,
            name=name or get_random_string(12),
            regex=regex,
            policy=ScopedPathRegex.Policy.BLOCK if block else ScopedPathRegex.Policy.ALLOW,
            **kwargs,
        )
        entry.tags.set(tags or [])
        entry.excluded_tags.set(excluded_tags or [])
        return entry

    # the tab bar

    def test_overview_has_the_three_tabs(self):
        enrolled_machine, _ = self.force_machine()
        self.login_with_view_enrolled_machine()
        response = self.client.get(reverse("santa:machine",
                                           args=(enrolled_machine.get_urlsafe_serial_number(),)))
        self.assertEqual(response.context["tab"], "overview")
        self.assertEqual([name for name, _, _ in response.context["tabs"]],
                         ["overview", "rules", "path_regexes"])
        self.assertContains(response, self.rules_url(enrolled_machine))
        self.assertContains(response, self.path_regexes_url(enrolled_machine))

    # the rules tab

    def test_machine_rules_redirect(self):
        self.login_redirect("machine_rules", "0123456789")

    def test_machine_rules_permission_denied(self):
        enrolled_machine, _ = self.force_machine()
        self.login()
        response = self.client.get(self.rules_url(enrolled_machine))
        self.assertEqual(response.status_code, 403)

    def test_machine_rules_machine_not_enrolled(self):
        self.login_with_view_enrolled_machine()
        response = self.client.get(reverse("santa:machine_rules", args=(get_random_string(12),)))
        self.assertEqual(response.status_code, 404)

    def test_machine_rules(self):
        enrolled_machine, configuration = self.force_machine()
        rule = self.force_binary_rule(configuration)
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.rules_url(enrolled_machine))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/machine_rules.html")
        self.assertEqual(response.context["tab"], "rules")
        self.assertEqual([row["identifier"] for row in response.context["rows"]],
                         [rule.target.identifier])
        self.assertContains(response, rule.target.identifier)
        self.assertContains(response, "Not yet on device")
        # the server column reads like the device one: the policy, then the version
        row = response.context["rows"][0]
        self.assertEqual((row["policy_display"], row["policy_version"]), ("Blocklist", 1))

    def test_machine_rules_no_rule(self):
        enrolled_machine, _ = self.force_machine()
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.rules_url(enrolled_machine))
        self.assertEqual(response.context["row_count"], 0)
        self.assertContains(response, "No rule.")

    def test_machine_rules_decided_by(self):
        enrolled_machine, configuration = self.force_machine()
        rule = self.force_binary_rule(configuration, serial_numbers=[enrolled_machine.serial_number])
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.rules_url(enrolled_machine))
        row = response.context["rows"][0]
        self.assertEqual(row["identifier"], rule.target.identifier)
        self.assertEqual(row["decided_by"], "Serial number")
        self.assertContains(response, "Serial number")

    def test_machine_rules_several_rules_for_a_target(self):
        enrolled_machine, configuration = self.force_machine()
        blocklist = self.force_binary_rule(configuration, policy=Rule.Policy.BLOCKLIST)
        Rule.objects.create(configuration=configuration, target=blocklist.target,
                            policy=Rule.Policy.ALLOWLIST,
                            serial_numbers=[enrolled_machine.serial_number])
        self.login_with_view_enrolled_machine("santa.view_rule")
        response = self.client.get(self.rules_url(enrolled_machine))
        row = response.context["rows"][0]
        self.assertEqual(row["policy_display"], "Allowlist")
        self.assertEqual(row["rules_in_configuration"], 2)
        self.assertIn("identifier=" + blocklist.target.identifier, row["rules_url"])
        self.assertNotIn("policy=", row["rules_url"])
        self.assertContains(response, "2 rules")

    def test_machine_rules_one_rule_for_a_target_has_no_link_to_the_rules(self):
        enrolled_machine, configuration = self.force_machine()
        self.force_binary_rule(configuration)
        self.login_with_view_enrolled_machine("santa.view_rule")
        response = self.client.get(self.rules_url(enrolled_machine))
        self.assertIsNone(response.context["rows"][0]["rules_url"])

    def test_machine_rules_skipped_cel_rule(self):
        enrolled_machine, configuration = self.force_machine()
        EnrolledMachine.objects.filter(pk=enrolled_machine.pk).update(santa_version="2024.5")
        self.force_binary_rule(configuration, policy=Rule.Policy.CEL, cel_expr="true")
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.rules_url(enrolled_machine))
        row = response.context["rows"][0]
        self.assertEqual(row["state"], MachineRule.State.SKIPPED)
        # nothing decided: the only rule in scope is one the client cannot evaluate
        self.assertIsNone(row["policy_display"])
        self.assertIsNone(row["decided_by"])
        self.assertContains(response, "Skipped")

    def test_machine_rules_a_rule_still_on_the_device_decides_nothing(self):
        enrolled_machine, configuration = self.force_machine()
        rule = self.force_binary_rule(configuration)
        SantaSyncClient(enrolled_machine).sync()
        Rule.objects.filter(pk=rule.pk).delete()
        self.login_with_view_enrolled_machine("santa.view_rule")
        response = self.client.get(self.rules_url(enrolled_machine))
        row = response.context["rows"][0]
        self.assertEqual(row["state"], MachineRule.State.STILL)
        self.assertIsNone(row["decided_by"])
        self.assertIsNone(row["rule_url"])

    # the filters

    def test_machine_rules_filter_counts(self):
        enrolled_machine, configuration = self.force_machine()
        self.force_binary_rule(configuration, policy=Rule.Policy.BLOCKLIST)
        self.force_binary_rule(configuration, policy=Rule.Policy.ALLOWLIST)
        force_rule(configuration=configuration, target_type=Target.Type.TEAM_ID)
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.rules_url(enrolled_machine))
        filters = {f["name"]: f for f in response.context["filters"]}
        state_values = {label: count for _, label, count in filters["state"]["values"]}
        self.assertEqual(state_values["All"], 3)
        self.assertEqual(state_values["Not yet on device"], 3)
        self.assertEqual(state_values["On device"], 0)
        type_values = {label: count for _, label, count in filters["target_type"]["values"]}
        self.assertEqual(type_values["Binary"], 2)
        self.assertEqual(type_values["Team ID"], 1)

    def test_machine_rules_filter_target_type(self):
        enrolled_machine, configuration = self.force_machine()
        binary_rule = self.force_binary_rule(configuration)
        force_rule(configuration=configuration, target_type=Target.Type.TEAM_ID)
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.rules_url(enrolled_machine), {"target_type": "BINARY"})
        self.assertEqual([row["identifier"] for row in response.context["rows"]],
                         [binary_rule.target.identifier])

    def test_machine_rules_filter_policy(self):
        enrolled_machine, configuration = self.force_machine()
        allowlist = self.force_binary_rule(configuration, policy=Rule.Policy.ALLOWLIST)
        self.force_binary_rule(configuration, policy=Rule.Policy.BLOCKLIST)
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.rules_url(enrolled_machine),
                                   {"policy": str(Rule.Policy.ALLOWLIST.value)})
        self.assertEqual([row["identifier"] for row in response.context["rows"]],
                         [allowlist.target.identifier])

    def test_machine_rules_filter_state(self):
        enrolled_machine, configuration = self.force_machine()
        synced = self.force_binary_rule(configuration)
        client = SantaSyncClient(enrolled_machine)
        client.sync()
        new_rule = self.force_binary_rule(configuration)
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.rules_url(enrolled_machine), {"state": "ON_DEVICE"})
        self.assertEqual([row["identifier"] for row in response.context["rows"]],
                         [synced.target.identifier])
        response = self.client.get(self.rules_url(enrolled_machine), {"state": "NOT_YET"})
        self.assertEqual([row["identifier"] for row in response.context["rows"]],
                         [new_rule.target.identifier])

    def test_machine_rules_filter_voting(self):
        enrolled_machine, configuration = self.force_machine()
        voting = self.force_binary_rule(configuration, is_voting_rule=True)
        self.force_binary_rule(configuration)
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.rules_url(enrolled_machine), {"voting": "yes"})
        self.assertEqual([row["identifier"] for row in response.context["rows"]],
                         [voting.target.identifier])

    def test_machine_rules_search(self):
        enrolled_machine, configuration = self.force_machine()
        rule = self.force_binary_rule(configuration)
        self.force_binary_rule(configuration)
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.rules_url(enrolled_machine),
                                   {"q": rule.target.identifier[:10]})
        self.assertEqual([row["identifier"] for row in response.context["rows"]],
                         [rule.target.identifier])

    def test_machine_rules_pagination(self):
        enrolled_machine, configuration = self.force_machine()
        for _ in range(3):
            self.force_binary_rule(configuration)
        self.login_with_view_enrolled_machine()
        self.user.items_per_page = 2
        self.user.save()
        response = self.client.get(self.rules_url(enrolled_machine))
        self.assertEqual(len(response.context["rows"]), 2)
        self.assertEqual(response.context["page_obj"].paginator.num_pages, 2)
        response = self.client.get(self.rules_url(enrolled_machine), {"page": 2})
        self.assertEqual(len(response.context["rows"]), 1)

    # the rule link

    def test_machine_rules_the_policy_links_to_the_rule_that_decided(self):
        enrolled_machine, configuration = self.force_machine()
        # a rule with no scope field reaches every machine, which is what decided for this one
        rule = self.force_binary_rule(configuration, policy=Rule.Policy.BLOCKLIST)
        self.login_with_view_enrolled_machine("santa.view_rule")
        response = self.client.get(self.rules_url(enrolled_machine))
        row = response.context["rows"][0]
        self.assertEqual(row["decided_by"], "All machines")
        url = row["rule_url"]
        self.assertIn(reverse("santa:configuration_rules", args=(configuration.pk,)), url)
        self.assertIn("identifier=" + rule.target.identifier, url)
        self.assertIn(f"policy={Rule.Policy.BLOCKLIST.value}", url)

    def test_machine_rules_no_rule_link_without_permission(self):
        enrolled_machine, configuration = self.force_machine()
        self.force_binary_rule(configuration)
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.rules_url(enrolled_machine))
        self.assertIsNone(response.context["rows"][0]["rule_url"])
        self.assertIsNone(response.context["rows"][0]["rules_url"])

    # the path regexes tab

    def test_machine_path_regexes_permission_denied(self):
        enrolled_machine, _ = self.force_machine()
        self.login()
        response = self.client.get(self.path_regexes_url(enrolled_machine))
        self.assertEqual(response.status_code, 403)

    def test_machine_path_regexes_none(self):
        enrolled_machine, _ = self.force_machine()
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.path_regexes_url(enrolled_machine))
        self.assertEqual(response.context["rows"], [])
        self.assertContains(response, "No pattern.")

    def test_machine_path_regexes_the_pattern_of_the_configuration(self):
        configuration = force_configuration(blocked_path_regex="/tmp/")
        enrolled_machine = force_enrolled_machine(configuration=configuration)
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.path_regexes_url(enrolled_machine))
        self.assertEqual(response.context["rows"],
                         [{"name": None, "regex": "/tmp/", "policy": "BLOCK",
                           "policy_display": "Block", "decided_by": "Configuration", "url": None}])

    def test_machine_path_regexes_the_winner_of_each_pattern(self):
        devs = Tag.objects.create(name=get_random_string(12))
        configuration = force_configuration(blocked_path_regex="/opt/")
        enrolled_machine = force_enrolled_machine(configuration=configuration, tags=[devs])
        # the Downloads table of the design: the allow entry wins by rank, so the path is not
        # blocked for a machine of the devs population, and the block entry is not a pattern
        winner = self.force_path_regex(configuration, "/Users/.*/Downloads/", block=False, tags=[devs])
        self.force_path_regex(configuration, "/Users/.*/Downloads/", block=True)
        # and an entry the machine is out of
        self.force_path_regex(configuration, "/tmp/", block=True, excluded_tags=[devs])
        self.login_with_view_enrolled_machine(extra_actions=("viewScopedPathRegex",))
        response = self.client.get(self.path_regexes_url(enrolled_machine))
        # the patterns the machine gets, in the order they are composed: the configuration first
        self.assertEqual(
            [(row["name"], row["regex"], row["policy_display"], row["decided_by"])
             for row in response.context["rows"]],
            [(winner.name, "/Users/.*/Downloads/", "Allow", "Tag"),
             (None, "/opt/", "Block", "Configuration")],
        )

    def test_machine_path_regexes_filter_policy(self):
        devs = Tag.objects.create(name=get_random_string(12))
        configuration = force_configuration(blocked_path_regex="/opt/")
        enrolled_machine = force_enrolled_machine(configuration=configuration, tags=[devs])
        allow = self.force_path_regex(configuration, "/Users/.*/Downloads/", block=False, tags=[devs])
        self.login_with_view_enrolled_machine(extra_actions=("viewScopedPathRegex",))
        response = self.client.get(self.path_regexes_url(enrolled_machine),
                                   {"policy": ScopedPathRegex.Policy.ALLOW})
        self.assertEqual([row["regex"] for row in response.context["rows"]], [allow.regex])
        # every value of the filter carries its count, over the whole table
        policy_filter = response.context["filters"][0]
        self.assertEqual(policy_filter["label"], "Policy")
        self.assertEqual({label: count for _, label, count in policy_filter["values"]},
                         {"All": 2, "Allow": 1, "Block": 1})

    def test_machine_path_regexes_search_the_name(self):
        devs = Tag.objects.create(name=get_random_string(12))
        configuration = force_configuration(blocked_path_regex="/opt/")
        enrolled_machine = force_enrolled_machine(configuration=configuration, tags=[devs])
        entry = self.force_path_regex(configuration, "/Users/.*/Downloads/", block=False,
                                      name="Downloads for the devs", tags=[devs])
        self.login_with_view_enrolled_machine(extra_actions=("viewScopedPathRegex",))
        response = self.client.get(self.path_regexes_url(enrolled_machine), {"q": "for the devs"})
        self.assertEqual([row["name"] for row in response.context["rows"]], [entry.name])

    def test_machine_path_regexes_search_the_pattern(self):
        configuration = force_configuration(blocked_path_regex="/opt/homebrew/")
        enrolled_machine = force_enrolled_machine(configuration=configuration)
        self.force_path_regex(configuration, "/tmp/", block=True)
        self.login_with_view_enrolled_machine(extra_actions=("viewScopedPathRegex",))
        # the pattern of the configuration has no name, and the search still finds it
        response = self.client.get(self.path_regexes_url(enrolled_machine), {"q": "homebrew"})
        self.assertEqual([(row["name"], row["regex"]) for row in response.context["rows"]],
                         [(None, "/opt/homebrew/")])
        self.assertEqual(response.context["row_count"], 1)

    def test_machine_path_regexes_hidden_without_permission(self):
        configuration = force_configuration()
        enrolled_machine = force_enrolled_machine(configuration=configuration)
        entry = self.force_path_regex(configuration, "/tmp/", block=True)
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.path_regexes_url(enrolled_machine))
        # the table only gives the entries the user may view. The machine still gets the pattern
        self.assertEqual(response.context["rows"], [])
        self.assertNotContains(response, entry.name)
        self.assertEqual(
            configuration.get_sync_server_config(enrolled_machine, (2026, 7))["blocked_path_regex"],
            "^(?:(?:/tmp/))",
        )


class SantaMachineRuleStateChoicesTestCase(TestCase):
    def test_state_labels(self):
        self.assertEqual(
            [(state.value, state.label) for state in MachineRule.State],
            [("ON_DEVICE", "On device"),
             ("NOT_YET", "Not yet on device"),
             ("STILL", "Still on device"),
             ("SKIPPED", "Skipped")],
        )
