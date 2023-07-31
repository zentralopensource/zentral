from .models import Artifact, Blueprint, FileVaultConfig
from zentral.contrib.inventory.terraform import TagResource
from zentral.utils.terraform import BoolAttr, FileBase64Attr, IntAttr, MapAttr, RefAttr, Resource, StringAttr


class ArtifactResource(Resource):
    tf_type = "zentral_mdm_artifact"
    tf_grouping_key = "mdm_artifacts"

    name = StringAttr(required=True)
    type = StringAttr(required=True)
    channel = StringAttr(required=True)
    platforms = StringAttr(many=True, required=True)
    install_during_setup_assistant = BoolAttr(default=False)
    auto_update = BoolAttr(default=True)
    reinstall_interval = IntAttr(default=0)
    reinstall_on_os_update = StringAttr(default="No")
    requires = RefAttr("zentral.contrib.mdm.terraform.ArtifactResource", many=True, default=list)


class FileVaultConfigResource(Resource):
    tf_type = "zentral_mdm_filevault_config"
    tf_grouping_key = "mdm_filevault_configs"

    name = StringAttr(required=True)
    escrow_location_display_name = StringAttr(required=True)
    at_login_only = BoolAttr(default=False)
    bypass_attempts = IntAttr(default=-1)
    show_recovery_key = BoolAttr(default=False)
    destroy_key_on_standby = BoolAttr(default=False)
    prk_rotation_interval_days = IntAttr(default=0)


class BlueprintResource(Resource):
    tf_type = "zentral_mdm_blueprint"
    tf_grouping_key = "mdm_blueprints"

    name = StringAttr(required=True)
    inventory_interval = IntAttr(default=86400)
    collect_apps = StringAttr(default=Blueprint.InventoryItemCollectionOption.NO.name,
                              source="get_collect_apps_display")
    collect_certificates = StringAttr(default=Blueprint.InventoryItemCollectionOption.NO.name,
                                      source="get_collect_certificates_display")
    collect_profiles = StringAttr(default=Blueprint.InventoryItemCollectionOption.NO.name,
                                  source="get_collect_profiles_display")
    filevault_config_id = RefAttr(FileVaultConfigResource)


# TODO: deduplicate Resource
class TagShardAttr(MapAttr):
    tag_id = RefAttr(TagResource, required=True)
    shard = IntAttr(required=True)


class BlueprintArtifactResource(Resource):
    tf_type = "zentral_mdm_blueprint_artifact"
    tf_grouping_key = "mdm_blueprints"

    blueprint_id = RefAttr(BlueprintResource, required=True)
    artifact_id = RefAttr(ArtifactResource, required=True)
    ios = BoolAttr(default=False)
    ios_max_version = StringAttr(default="")
    ios_min_version = StringAttr(default="")
    ipados = BoolAttr(default=False)
    ipados_max_version = StringAttr(default="")
    ipados_min_version = StringAttr(default="")
    macos = BoolAttr(default=False)
    macos_max_version = StringAttr(default="")
    macos_min_version = StringAttr(default="")
    tvos = BoolAttr(default=False)
    tvos_max_version = StringAttr(default="")
    tvos_min_version = StringAttr(default="")
    shard_modulo = IntAttr(default=100)
    default_shard = IntAttr(default=100)
    excluded_tag_ids = RefAttr(TagResource, many=True)
    tag_shards = TagShardAttr(many=True)


class ProfileResource(Resource):
    tf_type = "zentral_mdm_profile"
    tf_grouping_key = "mdm_artifacts"

    artifact_id = RefAttr(ArtifactResource, required=True)
    source = FileBase64Attr(rel_path="profiles", filename_source="get_export_filename")
    artifact_id = RefAttr(ArtifactResource, required=True, source="artifact_version.artifact")
    ios = BoolAttr(default=False, source="artifact_version.ios")
    ios_max_version = StringAttr(default="", source="artifact_version.ios_max_version")
    ios_min_version = StringAttr(default="", source="artifact_version.ios_min_version")
    ipados = BoolAttr(default=False, source="artifact_version.ipados")
    ipados_max_version = StringAttr(default="", source="artifact_version.ipados_max_version")
    ipados_min_version = StringAttr(default="", source="artifact_version.ipados_min_version")
    macos = BoolAttr(default=False, source="artifact_version.macos")
    macos_max_version = StringAttr(default="", source="artifact_version.macos_max_version")
    macos_min_version = StringAttr(default="", source="artifact_version.macos_min_version")
    tvos = BoolAttr(default=False, source="artifact_version.tvos")
    tvos_max_version = StringAttr(default="", source="artifact_version.tvos_max_version")
    tvos_min_version = StringAttr(default="", source="artifact_version.tvos_min_version")
    shard_modulo = IntAttr(default=100, source="artifact_version.shard_modulo")
    default_shard = IntAttr(default=100, source="artifact_version.default_shard")
    excluded_tag_ids = RefAttr(TagResource, many=True, source="artifact_version.excluded_tags")
    tag_shards = TagShardAttr(many=True, source="artifact_version.tag_shards")
    version = IntAttr(required=True, source="artifact_version.version")

    def get_pk(self):
        return self.instance.artifact_version.pk


def iter_resources():
    for blueprint in (Blueprint.objects
                               .select_related("filevault_config")
                               .prefetch_related("blueprintartifact_set__artifact",
                                                 "blueprintartifact_set__blueprint",
                                                 "blueprintartifact_set__excluded_tags",
                                                 "blueprintartifact_set__item_tags__tag").all()):
        yield BlueprintResource(blueprint)
        if blueprint.filevault_config:
            yield FileVaultConfigResource(blueprint.filevault_config)
        for blueprint_artifact in blueprint.blueprintartifact_set.all():
            yield BlueprintArtifactResource(blueprint_artifact)
    for filevault_config in FileVaultConfig.objects.all():
        yield FileVaultConfigResource(filevault_config)
    for artifact in Artifact.objects.prefetch_related("requires").filter(type=Artifact.Type.PROFILE):
        yield ArtifactResource(artifact)
        for artifact_version in artifact.artifactversion_set.select_related("profile").order_by("-version"):
            yield ProfileResource(artifact_version.profile)
