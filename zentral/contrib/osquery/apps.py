from zentral.utils.apps import ZentralAppConfig


class ZentralOsqueryAppConfig(ZentralAppConfig):
    name = "zentral.contrib.osquery"
    verbose_name = "Zentral Osquery contrib app"
    permission_models = (
        "automatictableconstruction",
        "configuration",
        "distributedquery",
        "enrollment",
        "filecategory",
        "filecarvingsession",
        "pack",
        "packquery",
        "query"
    )
