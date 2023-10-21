from zentral.contrib.inventory.terraform import MetaBusinessUnitResource, TagResource
from zentral.utils.terraform import BoolAttr, IntAttr, Resource, RefAttr, StringAttr
from .models import Configuration


class ConfigurationResource(Resource):
    tf_type = "zentral_munki_configuration"
    tf_grouping_key = "munki_configurations"

    name = StringAttr(required=True)
    description = StringAttr()
    inventory_apps_full_info_shard = IntAttr(default=100)
    principal_user_detection_sources = StringAttr(many=True)
    principal_user_detection_domains = StringAttr(many=True)
    collected_condition_keys = StringAttr(many=True)
    managed_installs_sync_interval_days = IntAttr(default=7)
    script_checks_run_interval_seconds = IntAttr(default=86400)
    auto_reinstall_incidents = BoolAttr(default=False)
    auto_failed_install_incidents = BoolAttr(default=False)


class EnrollmentResource(Resource):
    tf_type = "zentral_munki_enrollment"
    tf_grouping_key = "munki_configurations"

    configuration_id = RefAttr(ConfigurationResource, required=True)
    meta_business_unit_id = RefAttr(MetaBusinessUnitResource, required=True, source="secret.meta_business_unit")
    tag_ids = RefAttr(TagResource, many=True, source="secret.tags")
    serial_numbers = StringAttr(many=True, source="secret.serial_numbers")
    udids = StringAttr(many=True, source="secret.udids")
    quota = IntAttr(source="secret.quota")


def iter_resources():
    for configuration in Configuration.objects.all():
        yield ConfigurationResource(configuration)
        for enrollment in (configuration.enrollment_set
                                        .select_related("configuration", "secret__meta_business_unit")
                                        .prefetch_related("secret__tags")):
            yield EnrollmentResource(enrollment)
