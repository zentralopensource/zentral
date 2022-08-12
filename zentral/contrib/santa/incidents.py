import logging
from zentral.core.incidents import register_incident_class
from zentral.core.incidents.models import IncidentUpdate
from zentral.core.incidents.incidents import BaseIncident
from .models import Configuration


logger = logging.getLogger("zentral.core.santa.incidents")


class SyncIncident(BaseIncident):
    incident_type = "santa_sync"

    @classmethod
    def get_incident_key(cls, obj):
        return {"santa_cfg_pk": obj.pk}

    @classmethod
    def build_incident_update(cls, obj, severity):
        key = cls.get_incident_key(obj)
        return IncidentUpdate(cls.incident_type, key, severity)

    def get_objects(self):
        try:
            pk = int(self.key["santa_cfg_pk"])
        except (KeyError, ValueError):
            logger.error("Wrong santa sync incident key %s", self.key)
            return []
        else:
            return list(Configuration.objects.filter(pk=pk))

    def get_objects_for_display(self):
        configurations = self.get_objects()
        if configurations:
            yield ("Santa configuration",
                   ("santa.view_configuration",), configurations)

    def get_name(self):
        try:
            configuration = self.get_objects()[0]
        except IndexError:
            return "Unknown Santa configuration client out of sync"
        else:
            return f"Santa {configuration} configuration client out of sync"


register_incident_class(SyncIncident)
