from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.santa.models import Configuration, Rule, Target
from zentral.contrib.santa.terraform import ConfigurationResource, RuleResource


class SantaTerraformTestCase(TestCase):
    maxDiff = None

    # utils

    def force_configuration(self):
        return Configuration.objects.create(name=get_random_string(12))

    def force_rule(self, target_type=Target.Type.BINARY, policy=Rule.Policy.ALLOWLIST):
        target = Target.objects.create(
            type=target_type,
            identifier=get_random_string(length=64, allowed_chars='abcdef0123456789')
        )
        configuration = self.force_configuration()
        rule = Rule.objects.create(configuration=configuration, target=target, policy=policy)
        return rule

    # configuration

    def test_configuration(self):
        configuration = self.force_configuration()
        resource = ConfigurationResource(configuration)
        self.assertEqual(
            resource.to_representation(),
            (f'resource "zentral_santa_configuration" "configuration{configuration.pk}" {{\n'
             f'  name        = "{configuration.name}"\n'
             '  client_mode = "MONITOR"\n'
             '}')
        )

    def test_rule(self):
        rule = self.force_rule()
        resource = RuleResource(rule)
        self.assertEqual(
            resource.to_representation(),
            (f'resource "zentral_santa_rule" "rule{rule.pk}" {{\n'
             f'  configuration_id  = zentral_santa_configuration.configuration{rule.configuration.pk}.id\n'
             '  policy            = "ALLOWLIST"\n'
             '  target_type       = "BINARY"\n'
             f'  target_identifier = "{rule.target.identifier}"\n'
             '}')
        )
