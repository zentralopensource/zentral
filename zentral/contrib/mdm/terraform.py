from .models import Artifact, Blueprint
from zentral.contrib.inventory.terraform import TagResource
from zentral.utils.terraform import BoolAttr, IntAttr, MapAttr, RefAttr, Resource, StringAttr


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


def iter_resources():
    for blueprint in Blueprint.objects.prefetch_related("blueprintartifact_set__artifact",
                                                        "blueprintartifact_set__blueprint",
                                                        "blueprintartifact_set__excluded_tags",
                                                        "blueprintartifact_set__item_tags__tag").all():
        yield BlueprintResource(blueprint)
        for blueprint_artifact in blueprint.blueprintartifact_set.all():
            yield BlueprintArtifactResource(blueprint_artifact)
    for artifact in Artifact.objects.filter(type=Artifact.Type.PROFILE):
        for required_artifact in artifact.requires.all():
            yield ArtifactResource(required_artifact)
        yield ArtifactResource(artifact)
