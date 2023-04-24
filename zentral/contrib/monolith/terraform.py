from zentral.contrib.inventory.terraform import MetaBusinessUnitResource, TagResource
from zentral.utils.terraform import BoolAttr, IntAttr, MapAttr, Resource, RefAttr, StringAttr
from .models import Catalog, Condition, Manifest, SubManifest


class CatalogResource(Resource):
    tf_type = "zentral_monolith_catalog"
    tf_grouping_key = "monolith_catalogs"

    name = StringAttr(required=True)
    priority = IntAttr(default=0)


class ConditionResource(Resource):
    tf_type = "zentral_monolith_condition"
    tf_grouping_key = "monolith_conditions"

    name = StringAttr(required=True)
    predicate = StringAttr(required=True)


class ManifestResource(Resource):
    tf_type = "zentral_monolith_manifest"
    tf_grouping_key = "monolith_manifests"

    name = StringAttr(required=True)
    meta_business_unit_id = RefAttr(MetaBusinessUnitResource, required=True)


class EnrollmentResource(Resource):
    tf_type = "zentral_monolith_enrollment"
    tf_grouping_key = "monolith_manifests"

    manifest_id = RefAttr(ManifestResource, required=True)
    meta_business_unit_id = RefAttr(MetaBusinessUnitResource, required=True, source="secret.meta_business_unit")
    tag_ids = RefAttr(TagResource, many=True, source="secret.tags")
    serial_numbers = StringAttr(many=True, source="secret.serial_numbers")
    udids = StringAttr(many=True, source="secret.udids")
    quota = IntAttr(source="secret.quota")


class ManifestCatalogResource(Resource):
    tf_type = "zentral_monolith_manifest_catalog"
    tf_grouping_key = "monolith_manifests"

    manifest_id = RefAttr(ManifestResource, required=True)
    catalog_id = RefAttr(CatalogResource, required=True)
    tag_ids = RefAttr(TagResource, many=True)


class SubManifestResource(Resource):
    tf_type = "zentral_monolith_sub_manifest"
    tf_grouping_key = "monolith_sub_manifests"

    name = StringAttr(required=True)
    description = StringAttr()
    meta_business_unit_id = RefAttr(MetaBusinessUnitResource)


class ManifestSubManifestResource(Resource):
    tf_type = "zentral_monolith_manifest_sub_manifest"
    tf_grouping_key = "monolith_manifests"

    manifest_id = RefAttr(ManifestResource, required=True)
    sub_manifest_id = RefAttr(SubManifestResource, required=True)
    tag_ids = RefAttr(TagResource, many=True)


class TagShardAttr(MapAttr):
    tag_id = RefAttr(TagResource, required=True)
    shard = IntAttr(required=True)


class SubManifestPkgInfoResource(Resource):
    tf_type = "zentral_monolith_sub_manifest_pkg_info"
    tf_grouping_key = "monolith_sub_manifests"

    sub_manifest_id = RefAttr(SubManifestResource, required=True)
    key = StringAttr(required=True)
    pkg_info_name = StringAttr(required=True, source="pkg_info_name.name")
    featured_item = BoolAttr(default=False)
    condition_id = RefAttr(ConditionResource)
    shard_modulo = IntAttr(default=100)
    default_shard = IntAttr(default=100)
    excluded_tag_ids = RefAttr(TagResource, many=True)
    tag_shards = TagShardAttr(many=True)


def iter_resources():
    for catalog in Catalog.objects.filter(archived_at__isnull=True):
        yield CatalogResource(catalog)
    for condition in Condition.objects.all():
        yield ConditionResource(condition)
    for sub_manifest in SubManifest.objects.select_related("meta_business_unit"):
        yield SubManifestResource(sub_manifest)
        for sub_manifest_pkg_info in (sub_manifest.submanifestpkginfo_set
                                                  .select_related("pkg_info_name",
                                                                  "sub_manifest").all()):
            yield SubManifestPkgInfoResource(sub_manifest_pkg_info)
    for manifest in Manifest.objects.all():
        yield ManifestResource(manifest)
        for manifest_catalog in (manifest.manifestcatalog_set
                                         .prefetch_related("tags__meta_business_unit",
                                                           "tags__taxonomy")
                                         .select_related("catalog", "manifest")):
            yield ManifestCatalogResource(manifest_catalog)
        for enrollment in (manifest.enrollment_set
                                   .select_related("manifest", "secret__meta_business_unit")
                                   .prefetch_related("secret__tags")):
            yield EnrollmentResource(enrollment)
        for manifest_sub_manifest in (manifest.manifestsubmanifest_set
                                              .prefetch_related("tags__meta_business_unit",
                                                                "tags__taxonomy")
                                              .select_related("manifest", "sub_manifest")):
            yield ManifestSubManifestResource(manifest_sub_manifest)
