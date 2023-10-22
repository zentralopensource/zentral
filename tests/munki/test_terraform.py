from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import Tag
from zentral.contrib.munki.models import ScriptCheck
from zentral.contrib.munki.terraform import ConfigurationResource, EnrollmentResource, ScriptCheckResource
from .utils import force_configuration, force_enrollment, force_script_check


class MunkiTerraformTestCase(TestCase):
    maxDiff = None

    # configuration

    def test_default_configuration(self):
        cfg = force_configuration()
        resource = ConfigurationResource(cfg)
        self.assertEqual(
            resource.to_representation(),
            (f'resource "zentral_munki_configuration" "configuration{cfg.pk}" {{\n'
             f'  name = "{cfg.name}"\n'
             '}')
        )

    # enrollment

    def test_default_enrollment(self):
        e = force_enrollment()
        resource = EnrollmentResource(e)
        self.assertEqual(
            resource.to_representation(),
            (f'resource "zentral_munki_enrollment" "enrollment{e.pk}" {{\n'
             f'  configuration_id      = zentral_munki_configuration.configuration{e.configuration.pk}.id\n'
             '  meta_business_unit_id = zentral_meta_business_unit.metabusinessunit'
             f'{e.secret.meta_business_unit.pk}.id\n'
             '}')
        )

    # script check

    def test_default_script_check(self):
        sc = force_script_check()
        resource = ScriptCheckResource(sc)
        self.assertEqual(
            resource.to_representation(),
            (f'resource "zentral_munki_script_check" "scriptcheck{sc.pk}" {{\n'
             f'  name            = "{sc.compliance_check.name}"\n'
             '  source          = "echo yolo"\n'
             '  expected_result = "yolo"\n'
             '}')
        )

    def test_full_script_check(self):
        tag = Tag.objects.create(name=get_random_string(12))
        sc = force_script_check(
            type=ScriptCheck.Type.ZSH_BOOL,
            source="echo true",
            expected_result="true",
            arch_amd64=False,
            arch_arm64=True,
            min_os_version="14",
            max_os_version="15",
            tags=[tag],
        )
        description = get_random_string(12)
        sc.description = description
        sc.save()
        resource = ScriptCheckResource(sc)
        self.assertEqual(
            resource.to_representation(),
            (f'resource "zentral_munki_script_check" "scriptcheck{sc.pk}" {{\n'
             f'  name            = "{sc.compliance_check.name}"\n'
             '  type            = "ZSH_BOOL"\n'
             '  source          = "echo true"\n'
             '  expected_result = "true"\n'
             '  arch_amd64      = false\n'
             '  min_os_version  = "14"\n'
             '  max_os_version  = "15"\n'
             f'  tag_ids         = [zentral_tag.tag{tag.pk}.id]\n'
             '}')
        )
