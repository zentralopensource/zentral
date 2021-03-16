from zentral.utils.apps import ZentralAppConfig


class ZentralMonolithAppConfig(ZentralAppConfig):
    name = "zentral.contrib.monolith"
    verbose_name = "Zentral Monolith contrib app"
    permission_models = (
        "cacheserver",
        "catalog",
        "condition",
        "enrollment",
        "manifest",
        "manifestcatalog",
        "manifestenrollmentpackage",
        "manifestsubmanifest",
        "pkginfo",
        "pkginfoname",
        "printer",
        "printerppd",
        "submanifest",
        "submanifestattachment",
        "submanifestpkginfo",
    )
