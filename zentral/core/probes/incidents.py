import logging
from zentral.core.incidents import register_incident_class
from zentral.core.incidents.models import IncidentUpdate, Severity
from zentral.core.incidents.incidents import BaseIncident
from .models import ProbeSource


logger = logging.getLogger("zentral.core.munki.incidents")


class ProbeIncident(BaseIncident):
    incident_type = "probe"

    @classmethod
    def get_incident_key(cls, obj):
        return {"probe_pk": obj.pk}

    @classmethod
    def build_incident_update(cls, obj):
        try:
            severity = Severity(obj.incident_severity)
        except ValueError:
            return None
        key = cls.get_incident_key(obj)
        if key is None:
            return
        return IncidentUpdate(cls.incident_type, key, severity)

    def get_objects(self):
        try:
            pk = int(self.key["probe_pk"])
        except (KeyError, ValueError):
            logger.error("Wrong probe incident key %s", self.key)
            return ProbeSource.objects.none()
        return ProbeSource.objects.filter(pk=pk)

    def get_name(self):
        probe_source = self.get_objects().first()
        if probe_source is None:
            return "Unknown probe incident"
        else:
            return probe_source.name


register_incident_class(ProbeIncident)
