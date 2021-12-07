import logging
from zentral.core.incidents import register_incident_class
from zentral.core.incidents.models import IncidentUpdate, Severity
from zentral.core.incidents.incidents import BaseIncident


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


class MunkiFailedInstallIncident(BaseMunkiIncident):
    incident_type = "munki_failed_install"

    def get_name(self):
        name = self.key.get("munki_pkginfo_name", "???")
        version = self.key.get("munki_pkginfo_version", "???")
        return f"Munki pkg {name}/{version} failed install"


register_incident_class(MunkiFailedInstallIncident)


class MunkiReinstallIncident(BaseMunkiIncident):
    incident_type = "munki_reinstall"

    def get_name(self):
        name = self.key.get("munki_pkginfo_name", "???")
        version = self.key.get("munki_pkginfo_version", "???")
        return f"Munki pkg {name}/{version} reinstall"


register_incident_class(MunkiReinstallIncident)
