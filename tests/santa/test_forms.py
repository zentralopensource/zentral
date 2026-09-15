from unittest.mock import patch
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import Tag
from zentral.contrib.santa.forms import ConfigurationForm, RuleForm, ScopedClientModeForm
from zentral.contrib.santa.models import Configuration, Rule, ScopedClientMode
from tests.santa.utils import force_configuration, force_realm


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
        form = self.form(configuration, name="yolo")
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors["name"], ["A scoped client mode with this name already exists"])

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
