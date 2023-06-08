from django.test import TestCase
from zentral.contrib.mdm.models import Blueprint
from zentral.contrib.mdm.terraform import BlueprintResource
from .utils import force_blueprint


class MDMTerraformTestCase(TestCase):

    # blueprint

    def test_blueprint_resource_defaults(self):
        blueprint = force_blueprint()
        resource = BlueprintResource(blueprint)
        self.assertEqual(
            resource.to_representation(),
            f'resource "zentral_mdm_blueprint" "blueprint{blueprint.pk}" {{\n'
            f'  name = "{blueprint.name}"\n'
            '}'
        )

    def test_blueprint_resource_full(self):
        blueprint = force_blueprint()
        blueprint.inventory_interval = 77777
        blueprint.collect_apps = Blueprint.InventoryItemCollectionOption.MANAGED_ONLY
        blueprint.collect_certificates = Blueprint.InventoryItemCollectionOption.ALL
        blueprint.collect_profiles = Blueprint.InventoryItemCollectionOption.ALL
        blueprint.save()
        resource = BlueprintResource(blueprint)
        self.assertEqual(
            resource.to_representation(),
            f'resource "zentral_mdm_blueprint" "blueprint{blueprint.pk}" {{\n'
            f'  name                 = "{blueprint.name}"\n'
            '  inventory_interval   = 77777\n'
            '  collect_apps         = "MANAGED_ONLY"\n'
            '  collect_certificates = "ALL"\n'
            '  collect_profiles     = "ALL"\n'
            '}'
        )
