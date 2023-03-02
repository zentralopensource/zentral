from zentral.utils.apps import ZentralAppConfig


class ZentralOsqueryAppConfig(ZentralAppConfig):
    name = "zentral.contrib.osquery"
    default = True
    verbose_name = "Zentral Osquery contrib app"
    permission_models = (
        "automatictableconstruction",
        "configuration",
        "configurationpack",
        "distributedquery",
        "distributedqueryresult",
        "enrollment",
        "filecategory",
        "filecarvingsession",
        "pack",
        "packquery",
        "query"
    )
