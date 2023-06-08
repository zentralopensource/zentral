from .models import Blueprint
from zentral.utils.terraform import IntAttr, Resource, StringAttr


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
