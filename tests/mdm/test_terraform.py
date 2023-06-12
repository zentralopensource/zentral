from django.test import TestCase
from zentral.contrib.mdm.models import Artifact, Blueprint
from zentral.contrib.mdm.terraform import ArtifactResource, BlueprintResource
from .utils import force_artifact, force_blueprint


class MDMTerraformTestCase(TestCase):
    maxDiff = None

    # artifact

    def test_artifact_resource_defaults(self):
        artifact, _ = force_artifact()
        resource = ArtifactResource(artifact)
        self.assertEqual(
            resource.to_representation(),
            f'resource "zentral_mdm_artifact" "artifact{artifact.pk}" {{\n'
            f'  name      = "{artifact.name}"\n'
            '  type      = "Profile"\n'
            '  channel   = "Device"\n'
            '  platforms = ["macOS"]\n'
            '}'
        )

    def test_artifact_resource_full(self):
        required_artifact, _ = force_artifact()
        artifact, _ = force_artifact()
        artifact.install_during_setup_assistant = True
        artifact.auto_update = False
        artifact.reinstall_interval = 1
        artifact.reinstall_on_os_update = Artifact.ReinstallOnOSUpdate.MINOR
        artifact.save()
        artifact.requires.add(required_artifact)
        resource = ArtifactResource(artifact)
        self.assertEqual(
            resource.to_representation(),
            f'resource "zentral_mdm_artifact" "artifact{artifact.pk}" {{\n'
            f'  name                           = "{artifact.name}"\n'
            '  type                           = "Profile"\n'
            '  channel                        = "Device"\n'
            '  platforms                      = ["macOS"]\n'
            '  install_during_setup_assistant = true\n'
            '  auto_update                    = false\n'
            '  reinstall_interval             = 1\n'
            '  reinstall_on_os_update         = "Minor"\n'
            f'  requires                       = [zentral_mdm_artifact.artifact{required_artifact.pk}.id]\n'
            '}'
        )

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
