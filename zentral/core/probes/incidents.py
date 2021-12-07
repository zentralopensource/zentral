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
            return []
        else:
            return list(ProbeSource.objects.filter(pk=pk))

    def get_objects_for_display(self):
        probe_sources = self.get_objects()
        if probe_sources:
            yield ("Probe{}".format("" if len(probe_sources) == 1 else "s"),
                   ("probes.view_probesource",), probe_sources)

    def get_name(self):
        try:
            probe_source = self.get_objects()[0]
        except IndexError:
            return "Unknown probe incident"
        else:
            return probe_source.name


register_incident_class(ProbeIncident)
