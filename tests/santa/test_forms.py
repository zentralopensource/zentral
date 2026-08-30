from unittest.mock import patch
from django.test import TestCase
from zentral.contrib.santa.forms import ConfigurationForm, RuleForm
from zentral.contrib.santa.models import Configuration, Rule
from tests.santa.utils import force_configuration


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
