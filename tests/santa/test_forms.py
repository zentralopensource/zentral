from unittest.mock import patch
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import Tag
from zentral.contrib.santa.forms import (ConfigurationForm, RuleForm, ScopedClientModeForm,
                                         ScopedPathRegexForm, UpdateRuleForm)
from zentral.contrib.santa.models import Configuration, Rule, ScopedClientMode, ScopedPathRegex, Target
from tests.santa.utils import force_configuration, force_realm, force_rule, new_team_id


class RuleFormFieldPopTests(TestCase):
    def test_pops_custom_fields_when_no_compatible_policy(self):
        configuration = force_configuration()

        field = RuleForm.base_fields["policy"]
        old_choices = field.choices
        try:
            field.choices = [(Rule.Policy.ALLOWLIST, "Allow")]
            form = RuleForm(configuration=configuration)
            self.assertNotIn("custom_msg", form.fields)
            self.assertNotIn("custom_url", form.fields)
        finally:
            field.choices = old_choices

    def test_pops_custom_fields_when_compatible_policy(self):
        configuration = force_configuration()

        field = RuleForm.base_fields["policy"]
        old_choices = field.choices
        try:
            field.choices = [
                (Rule.Policy.ALLOWLIST, "Allow"),
                (Rule.Policy.BLOCKLIST, "Block"),
            ]
            form = RuleForm(configuration=configuration)
            self.assertIn("custom_msg", form.fields)
            self.assertIn("custom_url", form.fields)
        finally:
            field.choices = old_choices


class RuleFormAvailablePoliciesTests(TestCase):
    def policies(self, form):
        return [Rule.Policy(value) for value, _ in form.fields["policy"].choices]

    def test_a_free_target_offers_every_policy(self):
        form = RuleForm(configuration=force_configuration())
        self.assertEqual(self.policies(form), [Rule.Policy(value) for value, _ in Rule.Policy.rule_choices()])

    def test_a_fixed_target_offers_the_policies_it_has_left(self):
        configuration = force_configuration()
        team_id = new_team_id()
        force_rule(configuration=configuration, target_type=Target.Type.TEAM_ID, target_identifier=team_id,
                   policy=Rule.Policy.BLOCKLIST)
        form = RuleForm(configuration=configuration, team_id=team_id)
        self.assertNotIn("target_type", form.fields)
        # no Blocklist, taken, and no compiler policy on a Team ID
        self.assertEqual(self.policies(form),
                         [Rule.Policy.ALLOWLIST, Rule.Policy.SILENT_BLOCKLIST, Rule.Policy.CEL])

    def test_a_fixed_target_with_a_voting_rule_offers_nothing(self):
        configuration = force_configuration()
        team_id = new_team_id()
        force_rule(configuration=configuration, target_type=Target.Type.TEAM_ID, target_identifier=team_id,
                   is_voting_rule=True)
        form = RuleForm(configuration=configuration, team_id=team_id)
        self.assertEqual(self.policies(form), [])

    def test_a_fixed_target_pops_the_custom_fields_when_no_offered_policy_takes_them(self):
        configuration = force_configuration()
        team_id = new_team_id()
        block_rule = force_rule(configuration=configuration, target_type=Target.Type.TEAM_ID,
                                target_identifier=team_id, policy=Rule.Policy.BLOCKLIST)
        Rule.objects.create(configuration=configuration, target=block_rule.target, policy=Rule.Policy.CEL,
                            cel_expr="true")
        form = RuleForm(configuration=configuration, team_id=team_id)
        self.assertEqual(self.policies(form), [Rule.Policy.ALLOWLIST, Rule.Policy.SILENT_BLOCKLIST])
        self.assertNotIn("custom_msg", form.fields)
        self.assertNotIn("custom_url", form.fields)

    def test_the_update_form_offers_the_rule_policy_and_the_ones_left(self):
        configuration = force_configuration()
        team_id = new_team_id()
        allow_rule = force_rule(configuration=configuration, target_type=Target.Type.TEAM_ID,
                                target_identifier=team_id, policy=Rule.Policy.ALLOWLIST)
        Rule.objects.create(configuration=configuration, target=allow_rule.target, policy=Rule.Policy.BLOCKLIST)
        form = UpdateRuleForm(instance=allow_rule)
        self.assertEqual(self.policies(form),
                         [Rule.Policy.ALLOWLIST, Rule.Policy.SILENT_BLOCKLIST, Rule.Policy.CEL])


class ConfigurationFormClientCertAuthTests(TestCase):
    # the test configuration sets api.fqdn_mtls, so the mTLS endpoint is considered configured
    form_data = {
        "name": "cca",
        "client_mode": Configuration.MONITOR_MODE,
        "client_certificate_auth": True,
        "batch_size": 50,
        "full_sync_interval": 600,
        "allow_unknown_shard": 100,
        "enable_all_event_upload_shard": 0,
        "sync_incident_severity": 0,
        "banned_threshold": -26,
        "partially_allowlisted_threshold": 5,
        "globally_allowlisted_threshold": 50,
        "default_voting_weight": 0,
    }

    def test_client_certificate_auth_ok_when_fqdn_mtls_configured(self):
        form = ConfigurationForm(data=self.form_data)
        form.is_valid()
        self.assertNotIn("client_certificate_auth", form.errors)

    def test_client_certificate_auth_error_when_fqdn_mtls_missing(self):
        with patch("zentral.contrib.santa.forms.settings", {"api": {}}):
            form = ConfigurationForm(data=self.form_data)
            form.is_valid()
        self.assertEqual(
            form.errors["client_certificate_auth"],
            ["The server requiring the client cert for authentication is not configured."]
        )


class ConfigurationFormPathRegexTests(TestCase):
    form_data = {
        "name": "pr",
        "client_mode": Configuration.LOCKDOWN_MODE,
        "blocked_path_regex": "^/Users/[^/]+/Downloads/",
        "event_detail_source": Configuration.EventDetailSource.LOCAL,
        "batch_size": 50,
        "full_sync_interval": 600,
        "allow_unknown_shard": 100,
        "enable_all_event_upload_shard": 0,
        "sync_incident_severity": 0,
        "banned_threshold": -26,
        "partially_allowlisted_threshold": 5,
        "globally_allowlisted_threshold": 50,
        "default_voting_weight": 0,
    }

    def test_blocked_path_regex_in_lockdown_mode(self):
        form = ConfigurationForm(data=self.form_data)
        self.assertTrue(form.is_valid(), form.errors)


class ConfigurationFormEventDetailTests(TestCase):
    form_data = {
        "name": "ed",
        "client_mode": Configuration.MONITOR_MODE,
        "batch_size": 50,
        "full_sync_interval": 600,
        "allow_unknown_shard": 100,
        "enable_all_event_upload_shard": 0,
        "sync_incident_severity": 0,
        "banned_threshold": -26,
        "partially_allowlisted_threshold": 5,
        "globally_allowlisted_threshold": 50,
        "default_voting_weight": 0,
    }

    def test_source_is_required(self):
        # like client_mode: a choice field with a default is rendered with that default selected
        # and no empty option, so a browser always submits one
        form = ConfigurationForm(data=self.form_data)
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors["event_detail_source"], ["This field is required."])

    def test_local_source(self):
        form = ConfigurationForm(
            data=dict(self.form_data, event_detail_source=Configuration.EventDetailSource.LOCAL)
        )
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.save().get_event_detail(), (None, None))

    def test_voting_portal_source_requires_a_portal(self):
        form = ConfigurationForm(
            data=dict(self.form_data, event_detail_source=Configuration.EventDetailSource.VOTING_PORTAL)
        )
        self.assertFalse(form.is_valid())
        self.assertEqual(
            form.errors["event_detail_source"],
            ["Requires a voting realm with the user portal enabled"]
        )

    def test_custom_source_requires_an_url(self):
        form = ConfigurationForm(
            data=dict(self.form_data, event_detail_source=Configuration.EventDetailSource.CUSTOM)
        )
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors["event_detail_url"], ["This field is required"])

    def test_custom_source_with_an_url(self):
        form = ConfigurationForm(
            data=dict(self.form_data,
                      event_detail_source=Configuration.EventDetailSource.CUSTOM,
                      event_detail_url="https://www.example.com/blocked/")
        )
        self.assertTrue(form.is_valid(), form.errors)

    def test_local_source_clears_a_stored_url_and_label(self):
        configuration = force_configuration(
            event_detail_source=Configuration.EventDetailSource.CUSTOM,
            event_detail_url="https://www.example.com/blocked/",
            event_detail_text="Why?",
        )
        form = ConfigurationForm(
            instance=configuration,
            data=dict(self.form_data,
                      name=configuration.name,
                      event_detail_source=Configuration.EventDetailSource.LOCAL,
                      event_detail_url="https://www.example.com/blocked/",
                      event_detail_text="Why?")
        )
        self.assertTrue(form.is_valid(), form.errors)
        configuration = form.save()
        self.assertEqual(configuration.event_detail_url, "")
        self.assertEqual(configuration.event_detail_text, "")

    def test_voting_portal_source_does_not_require_a_text(self):
        realm = force_realm(user_portal=True)
        form = ConfigurationForm(
            data=dict(self.form_data,
                      voting_realm=realm.pk,
                      event_detail_source=Configuration.EventDetailSource.VOTING_PORTAL)
        )
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["event_detail_text"], "")
        self.assertEqual(form.save().get_event_detail()[1], Configuration.DEFAULT_EVENT_DETAIL_TEXT)


class ScopedClientModeFormTests(TestCase):
    def form(self, configuration, **data):
        data.setdefault("name", get_random_string(12))
        data.setdefault("client_mode", Configuration.MONITOR_MODE)
        data.setdefault("event_detail_source", ScopedClientMode.EventDetailSource.INHERIT)
        return ScopedClientModeForm(configuration=configuration, data=data)

    def test_inherit(self):
        form = self.form(force_configuration())
        self.assertTrue(form.is_valid())

    def test_voting_portal_without_a_configuration_realm(self):
        form = self.form(force_configuration(),
                         event_detail_source=ScopedClientMode.EventDetailSource.VOTING_PORTAL)
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors["event_detail_source"],
                         ["The configuration has no voting realm with the user portal enabled"])

    def test_voting_portal(self):
        configuration = force_configuration(voting_realm=force_realm(enabled_for_login=True, user_portal=True))
        form = self.form(configuration, event_detail_source=ScopedClientMode.EventDetailSource.VOTING_PORTAL)
        self.assertTrue(form.is_valid())

    def test_custom_without_url(self):
        form = self.form(force_configuration(),
                         event_detail_source=ScopedClientMode.EventDetailSource.CUSTOM)
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors["event_detail_url"], ["This field is required"])

    def test_conflicting_scope(self):
        tag = Tag.objects.create(name=get_random_string(12))
        form = self.form(force_configuration(),
                         serial_numbers="0123456789,9876543210",
                         excluded_serial_numbers="0123456789",
                         primary_users="yolo@zentral.com",
                         excluded_primary_users="yolo@zentral.com",
                         tags=[tag.pk],
                         excluded_tags=[tag.pk])
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors["excluded_serial_numbers"], ["Both included and excluded: 0123456789"])
        self.assertEqual(form.errors["excluded_primary_users"], ["Both included and excluded: yolo@zentral.com"])
        self.assertEqual(form.errors["excluded_tags"], [f"Both included and excluded: {tag}"])

    def test_duplicate_name(self):
        configuration = force_configuration()
        ScopedClientMode.objects.create(configuration=configuration, name="yolo",
                                        client_mode=Configuration.MONITOR_MODE)
        form = self.form(configuration, name="yolo", client_mode=Configuration.LOCKDOWN_MODE)
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors["__all__"],
                         ["Scoped client mode with this Configuration and Name already exists."])

    def test_one_entry_per_mode(self):
        configuration = force_configuration()
        ScopedClientMode.objects.create(configuration=configuration, name="yolo",
                                        client_mode=Configuration.MONITOR_MODE)
        form = self.form(configuration, client_mode=Configuration.MONITOR_MODE)
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors["__all__"],
                         ["Scoped client mode with this Configuration and Client mode already exists."])
        form = self.form(configuration, client_mode=Configuration.LOCKDOWN_MODE)
        self.assertTrue(form.is_valid(), form.errors)

    def test_same_name_on_another_configuration(self):
        ScopedClientMode.objects.create(configuration=force_configuration(), name="yolo",
                                        client_mode=Configuration.MONITOR_MODE)
        form = self.form(force_configuration(), name="yolo")
        self.assertTrue(form.is_valid(), form.errors)

    def test_update_keeps_its_own_name(self):
        configuration = force_configuration()
        scm = ScopedClientMode.objects.create(configuration=configuration, name="yolo",
                                              client_mode=Configuration.MONITOR_MODE)
        form = ScopedClientModeForm(
            configuration=configuration, instance=scm,
            data={"name": "yolo",
                  "client_mode": Configuration.LOCKDOWN_MODE,
                  "event_detail_source": ScopedClientMode.EventDetailSource.INHERIT},
        )
        self.assertTrue(form.is_valid(), form.errors)

    def test_save_sets_the_configuration(self):
        configuration = force_configuration()
        form = self.form(configuration, name="yolo")
        self.assertTrue(form.is_valid())
        scm = form.save()
        self.assertEqual(scm.configuration, configuration)
        self.assertEqual(str(scm), "yolo")
        self.assertEqual(scm.get_absolute_url(),
                         configuration.get_absolute_url() + f"#scoped-client-mode-{scm.pk}")


class ScopedPathRegexFormTests(TestCase):
    def form(self, configuration, **data):
        data.setdefault("name", get_random_string(12))
        data.setdefault("policy", ScopedPathRegex.Policy.ALLOW)
        data.setdefault("regex", "/Library/Example/")
        return ScopedPathRegexForm(configuration=configuration, data=data)

    def test_valid(self):
        self.assertTrue(self.form(force_configuration()).is_valid())

    def test_scoped_inline_flags_are_allowed(self):
        form = self.form(force_configuration(), regex="(?i:/library/)example/")
        self.assertTrue(form.is_valid(), form.errors)

    def test_bare_inline_flags(self):
        form = self.form(force_configuration(), regex="(?i)/library/")
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors["regex"],
                         ["Scoped inline flags are required, for example (?i:abc)"])

    def test_invalid_regex(self):
        form = self.form(force_configuration(), regex="/Library/[")
        self.assertFalse(form.is_valid())
        self.assertIn("Invalid regex:", form.errors["regex"][0])

    def test_capture_group(self):
        form = self.form(force_configuration(), regex="/Library/(Example)/")
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors["regex"],
                         ["Capture groups are not allowed, use a non capturing group: (?:abc)"])

    def test_named_group(self):
        form = self.form(force_configuration(), regex="/Library/(?P<name>Example)/")
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors["regex"],
                         ["Capture groups are not allowed, use a non capturing group: (?:abc)"])

    def test_non_capturing_group_is_allowed(self):
        form = self.form(force_configuration(), regex="/Library/(?:Example|Other)/")
        self.assertTrue(form.is_valid(), form.errors)

    def test_patterns_that_match_an_empty_path(self):
        # one of these in the combination opens it to every path
        for regex in ("^", "(?:)", "|", ".*", "a?", "(?:abc)?"):
            with self.subTest(regex=regex):
                form = self.form(force_configuration(), regex=regex)
                self.assertFalse(form.is_valid())
                self.assertEqual(
                    form.errors["regex"],
                    ["This pattern matches an empty path, so it matches every path. Use .+ and not .*"]
                )

    def test_a_pattern_that_matches_one_character_or_more(self):
        form = self.form(force_configuration(), regex=".+/Downloads/")
        self.assertTrue(form.is_valid(), form.errors)

    def test_conflicting_scope(self):
        form = self.form(force_configuration(),
                         serial_numbers="0123456789",
                         excluded_serial_numbers="0123456789")
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors["excluded_serial_numbers"],
                         ["Both included and excluded: 0123456789"])

    def test_duplicate_name(self):
        configuration = force_configuration()
        ScopedPathRegex.objects.create(configuration=configuration, name="yolo",
                                       policy=ScopedPathRegex.Policy.ALLOW, regex="/a/")
        form = self.form(configuration, name="yolo")
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors["__all__"],
                         ["Scoped path regex with this Configuration and Name already exists."])

    def test_one_entry_per_pattern_and_policy(self):
        configuration = force_configuration()
        ScopedPathRegex.objects.create(configuration=configuration, name="yolo",
                                       policy=ScopedPathRegex.Policy.ALLOW, regex="/a/")
        form = self.form(configuration, regex="/a/")
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors["__all__"],
                         ["Scoped path regex with this Configuration, Regex and Policy already exists."])
        form = self.form(configuration, regex="/a/", policy=ScopedPathRegex.Policy.BLOCK)
        self.assertTrue(form.is_valid(), form.errors)

    def test_a_pattern_longer_than_512_characters_is_refused(self):
        form = self.form(force_configuration(), regex="/a/" + "b" * 510)
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors["regex"], ["Ensure this value has at most 512 characters (it has 513)."])

    def test_a_leading_anchor_is_removed(self):
        # the composition removes it, so ^/a/ and /a/ are one pattern
        configuration = force_configuration()
        form = self.form(configuration, regex="^/a/")
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.save().regex, "/a/")
        form = self.form(configuration, regex="^/a/")
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors["__all__"],
                         ["Scoped path regex with this Configuration, Regex and Policy already exists."])

    def test_same_name_on_another_configuration(self):
        ScopedPathRegex.objects.create(configuration=force_configuration(), name="yolo",
                                       policy=ScopedPathRegex.Policy.ALLOW, regex="/a/")
        form = self.form(force_configuration(), name="yolo")
        self.assertTrue(form.is_valid(), form.errors)

    def test_save_sets_the_configuration(self):
        configuration = force_configuration()
        form = self.form(configuration, name="yolo")
        self.assertTrue(form.is_valid())
        spr = form.save()
        self.assertEqual(spr.configuration, configuration)
        self.assertEqual(str(spr), "yolo")


class ConfigurationFormPathRegexValidationTests(TestCase):
    form_data = dict(ConfigurationFormPathRegexTests.form_data, blocked_path_regex="")

    def form(self, instance=None, **data):
        return ConfigurationForm(data=dict(self.form_data, **data), instance=instance)

    def test_a_new_pattern_that_does_not_compile_is_refused(self):
        form = self.form(blocked_path_regex=r"/Users/\p{L}+/")
        self.assertFalse(form.is_valid())
        self.assertIn("Invalid regex:", form.errors["blocked_path_regex"][0])

    def test_a_new_pattern_with_unscoped_inline_flags_is_refused(self):
        form = self.form(blocked_path_regex="(?i)/downloads/")
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors["blocked_path_regex"],
                         ["Scoped inline flags are required, for example (?i:abc)"])

    def test_a_new_pattern_that_matches_an_empty_path_is_refused(self):
        form = self.form(blocked_path_regex=".*")
        self.assertFalse(form.is_valid())
        self.assertEqual(
            form.errors["blocked_path_regex"],
            ["This pattern matches an empty path, so it matches every path. Use .+ and not .*"]
        )

    def test_a_pattern_stored_before_the_composition_does_not_block_another_edit(self):
        # it is still enforced, so it must not stop an edit of another field
        configuration = force_configuration(blocked_path_regex=r"/Users/\p{L}+/")
        form = self.form(instance=configuration, name="renamed",
                         blocked_path_regex=r"/Users/\p{L}+/")
        self.assertTrue(form.is_valid(), form.errors)

    def test_changing_a_pattern_that_was_stored_before_the_composition_is_validated(self):
        configuration = force_configuration(blocked_path_regex=r"/Users/\p{L}+/")
        form = self.form(instance=configuration, blocked_path_regex=r"/Users/\p{L}+/Downloads/")
        self.assertFalse(form.is_valid())
        self.assertIn("Invalid regex:", form.errors["blocked_path_regex"][0])
