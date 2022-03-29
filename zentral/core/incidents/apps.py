from zentral.utils.apps import ZentralAppConfig


class ZentralIncidentsAppConfig(ZentralAppConfig):
    name = "zentral.core.incidents"
    default = True
    verbose_name = "Zentral incidents app"
    permission_models = ("incident", "machineincident")
