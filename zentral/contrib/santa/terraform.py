from zentral.contrib.inventory.terraform import MetaBusinessUnitResource, TagResource
from zentral.utils.terraform import BoolAttr, IntAttr, Resource, RefAttr, StringAttr
from .models import Configuration


class ConfigurationResource(Resource):
    tf_type = "zentral_santa_configuration"
    tf_grouping_key = "santa_configurations"

    name = StringAttr(required=True)
    client_mode = IntAttr(default=1)
    client_certificate_auth = BoolAttr(default=False)
    batch_size = IntAttr(default=50)
    full_sync_interval = IntAttr(default=600)
    enable_bundles = BoolAttr(default=False)
    enable_transitive_rules = BoolAttr(default=False)
    allowed_path_regex = StringAttr()
    blocked_path_regex = StringAttr()
    block_usb_mount = BoolAttr(default=False)
    remount_usb_mode = StringAttr(many=True)
    allow_unknown_shard = IntAttr(default=100)
    enable_all_event_upload_shard = IntAttr(default=0)
    sync_incident_severity = IntAttr(default=0)


class EnrollmentResource(Resource):
    tf_type = "zentral_santa_enrollment"
    tf_grouping_key = "santa_configurations"

    configuration_id = RefAttr(ConfigurationResource, required=True)
    meta_business_unit_id = RefAttr(MetaBusinessUnitResource, required=True, source="secret.meta_business_unit")
    tag_ids = RefAttr(TagResource, many=True, source="secret.tags")
    serial_numbers = StringAttr(many=True, source="secret.serial_numbers")
    udids = StringAttr(many=True, source="secret.udids")
    quota = IntAttr(source="secret.quota")


class RuleResource(Resource):
    tf_type = "zentral_santa_rule"
    tf_grouping_key = "santa_configurations"

    configuration_id = RefAttr(ConfigurationResource, required=True)
    policy = IntAttr(required=True)
    target_type = StringAttr(required=True, source="target.type")
    target_identifier = StringAttr(required=True, source="target.identifier")
    description = StringAttr()
    custom_message = StringAttr(source="custom_msg")
    primary_users = StringAttr(many=True)
    excluded_primary_users = StringAttr(many=True)
    serial_numbers = StringAttr(many=True)
    excluded_serial_numbers = StringAttr(many=True)
    tag_ids = RefAttr(TagResource, many=True)
    excluded_tag_ids = RefAttr(TagResource, many=True)


def iter_resources():
    for configuration in Configuration.objects.all():
        yield ConfigurationResource(configuration)
        for enrollment in (configuration.enrollment_set
                                        .select_related("configuration", "secret__meta_business_unit")
                                        .prefetch_related("secret__tags")):
            yield EnrollmentResource(enrollment)
        for rule in (configuration.rule_set
                                  .select_related("configuration", "target")
                                  .prefetch_related("tags", "excluded_tags")
                                  .all()):
            yield RuleResource(rule)
