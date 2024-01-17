from zentral.utils.apps import ZentralAppConfig


class ZentralMonolithAppConfig(ZentralAppConfig):
    name = "zentral.contrib.monolith"
    default = True
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
        "repository",
        "submanifest",
        "submanifestpkginfo",
    )
