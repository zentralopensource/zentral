from .models import Artifact, Blueprint
from zentral.utils.terraform import BoolAttr, IntAttr, RefAttr, Resource, StringAttr


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


def iter_resources():
    for blueprint in Blueprint.objects.all():
        yield BlueprintResource(blueprint)
    for artifact in Artifact.objects.filter(type=Artifact.Type.PROFILE):
        for required_artifact in artifact.requires.all():
            yield ArtifactResource(required_artifact)
        yield ArtifactResource(artifact)
