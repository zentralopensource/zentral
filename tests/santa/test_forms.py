from django.test import TestCase
from zentral.contrib.santa.forms import RuleForm
from zentral.contrib.santa.models import Rule
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
