from zentral.utils.apps import ZentralAppConfig


class ZentralZendeskAppConfig(ZentralAppConfig):
    name = "zentral.contrib.zendesk"
    default = True
    verbose_name = "Zentral Zendesk contrib app"
