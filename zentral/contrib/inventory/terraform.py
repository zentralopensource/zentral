from zentral.utils.terraform import BoolAttr, Resource, RefAttr, StringAttr
from .models import JMESPathCheck


class MetaBusinessUnitResource(Resource):
    tf_type = "zentral_meta_business_unit"
    tf_grouping_key = "meta_business_units"

    name = StringAttr(required=True)
    api_enrollment_enabled = BoolAttr()


class TaxonomyResource(Resource):
    tf_type = "zentral_taxonomy"
    tf_grouping_key = "tags"

    name = StringAttr(required=True)


class TagResource(Resource):
    tf_type = "zentral_tag"
    tf_grouping_key = "tags"

    taxonomy_id = RefAttr(TaxonomyResource)
    name = StringAttr(required=True)
    color = StringAttr(default="0079bf")


class JMESPathCheckResource(Resource):
    tf_type = "zentral_jmespath_check"
    tf_grouping_key = "jmespath_checks"

    name = StringAttr(required=True, source="compliance_check.name")
    description = StringAttr(source="compliance_check.description")
    source_name = StringAttr(required=True)
    platforms = StringAttr(many=True)
    tag_ids = RefAttr(TagResource, many=True)
    jmespath_expression = StringAttr(required=True)


def iter_compliance_check_resources():
    for cc in (JMESPathCheck.objects.select_related("compliance_check")
                                    .prefetch_related("tags__meta_business_unit",
                                                      "tags__taxonomy").all().order_by("pk")):
        yield JMESPathCheckResource(cc)
