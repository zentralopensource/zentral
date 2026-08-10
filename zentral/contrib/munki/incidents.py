import logging
from zentral.core.incidents import register_incident_class
from zentral.core.incidents.models import IncidentUpdate, Severity
from zentral.core.incidents.incidents import BaseIncident
from .models import MunkiState


logger = logging.getLogger("zentral.contrib.munki.incidents")


class BaseMunkiIncident(BaseIncident):
    severity = Severity.MAJOR

    @classmethod
    def get_incident_key(cls, name, version):
        return {"munki_pkginfo_name": name, "munki_pkginfo_version": version}

    @classmethod
    def build_incident_update(cls, name, version, severity=None):
        key = cls.get_incident_key(name, version)
        if key is None:
            return
        if severity is None:
            severity = cls.severity
        return IncidentUpdate(cls.incident_type, key, severity)

    def get_objects(self):
        try:
            name = self.key["munki_pkginfo_name"]
            version = self.key["munki_pkginfo_version"]
        except KeyError:
            logger.error("Wrong Munki incident key %s", self.key)
            return []
        try:
            from zentral.contrib.monolith.models import PkgInfo
        except ModuleNotFoundError:
            return []
        else:
            return list(PkgInfo.objects.filter(name__name=name, version=version))

    def get_objects_for_display(self):
        pkg_infos = self.get_objects()
        if pkg_infos:
            yield ("PkgInfo{}".format("" if len(pkg_infos) == 1 else "s"),
                   ("monolith.view_pkginfoname",), pkg_infos)


class MunkiInstallFailedIncident(BaseMunkiIncident):
    incident_type = "munki_install_failed"

    def get_name(self):
        name = self.key.get("munki_pkginfo_name", "???")
        version = self.key.get("munki_pkginfo_version", "???")
        return f"Munki pkg {name}/{version} install failed"


register_incident_class(MunkiInstallFailedIncident)


class MunkiReinstallIncident(BaseMunkiIncident):
    incident_type = "munki_reinstall"

    def get_name(self):
        name = self.key.get("munki_pkginfo_name", "???")
        version = self.key.get("munki_pkginfo_version", "???")
        return f"Munki pkg {name}/{version} reinstall"


register_incident_class(MunkiReinstallIncident)


class MunkiAgentUnhealthyIncident(BaseIncident):
    """The munki agent on a machine is not completing runs.

    Machine-scoped: the events carry a serial, so this opens a MachineIncident. One incident per machine,
    escalating in place as the diagnosis changes — the reason travels in the event payload, never in the
    key, or every change of diagnosis would open a second incident and leave the first one open.
    """
    incident_type = "munki_agent_unhealthy"

    @classmethod
    def get_incident_key(cls, serial_number):
        return {"munki_msn": serial_number}

    def get_objects(self):
        try:
            serial_number = self.key["munki_msn"]
        except KeyError:
            logger.error("Wrong munki agent unhealthy incident key %s", self.key)
            return []
        return list(MunkiState.objects.filter(machine_serial_number=serial_number))

    def get_objects_for_display(self):
        munki_states = self.get_objects()
        if munki_states:
            yield ("Munki state", ("munki.view_munkistate",), munki_states)

    def get_name(self):
        try:
            serial_number = self.key["munki_msn"]
        except KeyError:
            return "Unknown machine munki agent is unhealthy"
        return f"Munki agent on {serial_number} is not completing runs"


register_incident_class(MunkiAgentUnhealthyIncident)
