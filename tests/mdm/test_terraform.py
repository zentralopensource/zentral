from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import Tag
from zentral.contrib.mdm.models import Artifact, Blueprint
from zentral.contrib.mdm.terraform import (ArtifactResource,
                                           BlueprintResource, BlueprintArtifactResource,
                                           FileVaultConfigResource,
                                           ProfileResource,
                                           RecoveryPasswordConfigResource)
from .utils import (force_artifact, force_blueprint, force_blueprint_artifact,
                    force_filevault_config, force_recovery_password_config)


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

    # profile

    def test_profile_resource_defaults(self):
        artifact, (profile_av,) = force_artifact()
        profile = profile_av.profile
        profile_filename = f"{artifact.name.lower()}_{profile.pk}_v1.mobileconfig"
        resource = ProfileResource(profile)
        self.assertEqual(
            resource.to_representation(),
            f'resource "zentral_mdm_profile" "profile{ profile.pk }" {{\n'
            f'  artifact_id = zentral_mdm_artifact.artifact{ artifact.pk}.id\n'
            f'  source      = filebase64("${{path.module}}/profiles/{profile_filename}")\n'
            '  macos       = true\n'
            '  version     = 1\n'
            '}'
        )

    def test_profile_resource_full(self):
        artifact, (profile_av,) = force_artifact()
        profile = profile_av.profile
        profile.filename = "{}.mobileconfig".format(get_random_string(12))
        profile.save()
        profile_filename = f"{artifact.name.lower()}_{profile.pk}_v1.mobileconfig"
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        profile_av.macos_min_version = "13.3.1"
        profile_av.default_shard = 0
        profile_av.shard_modulo = 10
        profile_av.save()
        profile_av.excluded_tags.add(excluded_tag)
        profile_av.item_tags.create(tag=shard_tag, shard=10)
        resource = ProfileResource(profile)
        self.assertEqual(
            resource.to_representation(),
            f'resource "zentral_mdm_profile" "profile{ profile.pk }" {{\n'
            f'  artifact_id       = zentral_mdm_artifact.artifact{ artifact.pk}.id\n'
            f'  source            = filebase64("${{path.module}}/profiles/{profile_filename}")\n'
            '  macos             = true\n'
            '  macos_min_version = "13.3.1"\n'
            '  shard_modulo      = 10\n'
            '  default_shard     = 0\n'
            f'  excluded_tag_ids  = [zentral_tag.tag{excluded_tag.pk}.id]\n'
            f'  tag_shards        = [{{ tag_id = zentral_tag.tag{shard_tag.pk}.id, shard = 10 }}]\n'
            '  version           = 1\n'
            '}'
        )

    # FileVault config

    def test_filevault_config_resource_defaults(self):
        filevault_config = force_filevault_config()
        resource = FileVaultConfigResource(filevault_config)
        self.assertEqual(
            resource.to_representation(),
            f'resource "zentral_mdm_filevault_config" "filevaultconfig{filevault_config.pk}" {{\n'
            f'  name                         = "{filevault_config.name}"\n'
            f'  escrow_location_display_name = "{filevault_config.escrow_location_display_name}"\n'
            '}'
        )

    def test_filevault_config_resource_full(self):
        filevault_config = force_filevault_config()
        filevault_config.at_login_only = True
        filevault_config.bypass_attempts = 1
        filevault_config.show_recovery_key = True
        filevault_config.destroy_key_on_standby = True
        filevault_config.prk_rotation_interval_days = 90
        filevault_config.save()

        resource = FileVaultConfigResource(filevault_config)
        self.assertEqual(
            resource.to_representation(),
            f'resource "zentral_mdm_filevault_config" "filevaultconfig{filevault_config.pk}" {{\n'
            f'  name                         = "{filevault_config.name}"\n'
            f'  escrow_location_display_name = "{filevault_config.escrow_location_display_name}"\n'
            '  at_login_only                = true\n'
            '  bypass_attempts              = 1\n'
            '  show_recovery_key            = true\n'
            '  destroy_key_on_standby       = true\n'
            '  prk_rotation_interval_days   = 90\n'
            '}'
        )

    # recovery password config

    def test_recovery_password_resource_defaults(self):
        rp_config = force_recovery_password_config()
        resource = RecoveryPasswordConfigResource(rp_config)
        self.assertEqual(
            resource.to_representation(),
            f'resource "zentral_mdm_recovery_password_config" "recoverypasswordconfig{rp_config.pk}" {{\n'
            f'  name = "{rp_config.name}"\n'
            '}'
        )

    def test_recovery_password_resource_full(self):
        rp_config = force_recovery_password_config(
            rotation_interval_days=90,
            static_password="12345678",
        )
        rp_config.rotate_firmware_password = True
        rp_config.save()
        resource = RecoveryPasswordConfigResource(rp_config)
        self.assertEqual(
            resource.to_representation(),
            f'resource "zentral_mdm_recovery_password_config" "recoverypasswordconfig{rp_config.pk}" {{\n'
            f'  name                     = "{rp_config.name}"\n'
            '  dynamic_password         = false\n'
            f'  static_password          = var.recoverypasswordconfig{rp_config.pk}_static_password\n'
            '  rotation_interval_days   = 90\n'
            '  rotate_firmware_password = true\n'
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
        filevault_config = force_filevault_config()
        blueprint = force_blueprint(filevault_config=filevault_config)
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
            f'  filevault_config_id  = zentral_mdm_filevault_config.filevaultconfig{filevault_config.pk}.id\n'
            '}'
        )

    # blueprint artifact

    def test_blueprint_artifact_resource_defaults(self):
        blueprint_artifact, _, _ = force_blueprint_artifact()
        resource = BlueprintArtifactResource(blueprint_artifact)
        self.assertEqual(
            resource.to_representation(),
            f'resource "zentral_mdm_blueprint_artifact" "blueprintartifact{blueprint_artifact.pk}" {{\n'
            f'  blueprint_id = zentral_mdm_blueprint.blueprint{blueprint_artifact.blueprint.pk}.id\n'
            f'  artifact_id  = zentral_mdm_artifact.artifact{blueprint_artifact.artifact.pk}.id\n'
            '  macos        = true\n'
            '}'
        )

    def test_blueprint_artifact_resource_full(self):
        blueprint_artifact, _, _ = force_blueprint_artifact()
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        blueprint_artifact.default_shard = 0
        blueprint_artifact.shard_modulo = 10
        blueprint_artifact.macos_max_version = "14"
        blueprint_artifact.save()
        blueprint_artifact.excluded_tags.add(excluded_tag)
        blueprint_artifact.item_tags.create(tag=shard_tag, shard=10)
        resource = BlueprintArtifactResource(blueprint_artifact)
        self.assertEqual(
            resource.to_representation(),
            f'resource "zentral_mdm_blueprint_artifact" "blueprintartifact{blueprint_artifact.pk}" {{\n'
            f'  blueprint_id      = zentral_mdm_blueprint.blueprint{blueprint_artifact.blueprint.pk}.id\n'
            f'  artifact_id       = zentral_mdm_artifact.artifact{blueprint_artifact.artifact.pk}.id\n'
            '  macos             = true\n'
            '  macos_max_version = "14"\n'
            '  shard_modulo      = 10\n'
            '  default_shard     = 0\n'
            f'  excluded_tag_ids  = [zentral_tag.tag{excluded_tag.pk}.id]\n'
            f'  tag_shards        = [{{ tag_id = zentral_tag.tag{shard_tag.pk}.id, shard = 10 }}]\n'
            '}'
        )
