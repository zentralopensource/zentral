from . import register_incident_class
from .models import Incident


class BaseIncident:
    incident_type = "base"

    @classmethod
    def get_incident_key(cls, obj):
        return None

    @classmethod
    def get_incidents(cls, obj):
        key = cls.get_incident_key(obj)
        if key is not None:
            return Incident.objects.filter(incident_type=cls.incident_type, key=key)
        else:
            return Incident.objects.none()

    def __init__(self, incident):
        self.incident = incident
        self.key = incident.key
        self.pk = incident.pk

    def get_objects(self, key):
        return []

    def get_objects_for_display(self):
        return []

    def get_name(self):
        return f"{self.incident_type} incident {self.incident.pk or '∅'}"


register_incident_class(BaseIncident)
