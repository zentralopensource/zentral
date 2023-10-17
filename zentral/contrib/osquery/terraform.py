from zentral.contrib.inventory.terraform import MetaBusinessUnitResource, TagResource
from zentral.utils.terraform import BoolAttr, IntAttr, MapAttr, Resource, RefAttr, StringAttr, StringMapAttr
from .models import AutomaticTableConstruction, Configuration, FileCategory, Pack, Query


class FileCategoryResource(Resource):
    tf_type = "zentral_osquery_file_category"
    tf_grouping_key = "osquery_file_categories"

    name = StringAttr(required=True)
    description = StringAttr()
    file_paths = StringAttr(many=True)
    exclude_paths = StringAttr(many=True)
    file_paths_queries = StringAttr(many=True)
    access_monitoring = BoolAttr(default=False)


class ATCResource(Resource):
    tf_type = "zentral_osquery_atc"
    tf_grouping_key = "osquery_automatic_table_constructions"

    name = StringAttr(required=True)
    description = StringAttr()
    table_name = StringAttr(required=True)
    query = StringAttr(required=True)
    path = StringAttr(required=True)
    columns = StringAttr(many=True, required=True)
    platforms = StringAttr(many=True, required=True)


class ConfigurationResource(Resource):
    tf_type = "zentral_osquery_configuration"
    tf_grouping_key = "osquery_configurations"

    name = StringAttr(required=True)
    description = StringAttr()
    inventory = BoolAttr(default=True)
    inventory_apps = BoolAttr(default=False)
    inventory_ec2 = BoolAttr(default=False)
    inventory_interval = IntAttr(default=86400)
    options = StringMapAttr()
    atc_ids = RefAttr(ATCResource, many=True, source="automatic_table_constructions")
    file_category_ids = RefAttr(FileCategoryResource, many=True, source="file_categories")


class EnrollmentResource(Resource):
    tf_type = "zentral_osquery_enrollment"
    tf_grouping_key = "osquery_configurations"

    configuration_id = RefAttr(ConfigurationResource, required=True)
    osquery_release = StringAttr()
    meta_business_unit_id = RefAttr(MetaBusinessUnitResource, required=True, source="secret.meta_business_unit")
    tag_ids = RefAttr(TagResource, many=True, source="secret.tags")
    serial_numbers = StringAttr(many=True, source="secret.serial_numbers")
    udids = StringAttr(many=True, source="secret.udids")
    quota = IntAttr(source="secret.quota")


class PackResource(Resource):
    tf_type = "zentral_osquery_pack"
    tf_grouping_key = "osquery_packs"

    name = StringAttr(required=True)
    description = StringAttr()
    discovery_queries = StringAttr(many=True)
    shard = IntAttr()
    event_routing_key = StringAttr()


class QuerySchedulingAttr(MapAttr):
    can_be_denylisted = BoolAttr(default=True)
    interval = IntAttr(required=True)
    log_removed_actions = BoolAttr(default=True)
    pack_id = RefAttr(PackResource, required=True)
    shard = IntAttr()
    snapshot_mode = BoolAttr(default=False)


class QueryResource(Resource):
    tf_type = "zentral_osquery_query"
    tf_grouping_key = "osquery_queries"

    name = StringAttr(required=True)
    sql = StringAttr(required=True)
    platforms = StringAttr(many=True, required=True)
    minimum_osquery_version = StringAttr()
    description = StringAttr()
    value = StringAttr()
    compliance_check_enabled = BoolAttr(default=False)
    tag_id = RefAttr(TagResource, required=False)
    scheduling = QuerySchedulingAttr(source="pack_query")


class ConfigurationPackResource(Resource):
    tf_type = "zentral_osquery_configuration_pack"
    tf_grouping_key = "osquery_configurations"

    configuration_id = RefAttr(ConfigurationResource, required=True)
    pack_id = RefAttr(PackResource, required=True)
    tag_ids = RefAttr(TagResource, many=True)


def iter_resources():
    for atc in AutomaticTableConstruction.objects.all():
        yield ATCResource(atc)
    for file_category in FileCategory.objects.all():
        yield FileCategoryResource(file_category)
    for pack in Pack.objects.all():
        yield PackResource(pack)
    for configuration in (Configuration.objects.prefetch_related("automatic_table_constructions",
                                                                 "file_categories").all()):
        yield ConfigurationResource(configuration)
        for enrollment in (configuration.enrollment_set
                                        .select_related("configuration", "secret__meta_business_unit")
                                        .prefetch_related("secret__tags")):
            yield EnrollmentResource(enrollment)
        for configuration_pack in (configuration.configurationpack_set.select_related("configuration")
                                                                      .prefetch_related("tags__meta_business_unit",
                                                                                        "tags__taxonomy").all()):
            yield ConfigurationPackResource(configuration_pack)
    for query in Query.objects.all():
        yield QueryResource(query)
