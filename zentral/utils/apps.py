from importlib import import_module
import logging
import os.path
import re

from django.apps import AppConfig

from pbac.engine import engine


logger = logging.getLogger('zentral.utils.apps')


class ZentralAppConfig(AppConfig):
    permission_models = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.compliance_checks_module = None
        self.events_module = None
        self.events_templates_dir = None
        self.incidents_module = None
        self.provisioning_module = None
        self.pbac_module = None

    def ready(self):
        """
        To run some extra code when Django starts
        """
        self.import_compliance_checks()
        self.import_events()
        self.import_incidents()
        self.import_provisioning()
        self.import_pbac_module()
        self.register_legacy_perms()

    def _import_submodule(self, submodule_name):
        try:
            submodule = import_module(f"{self.name}.{submodule_name}")
        except ModuleNotFoundError:
            pass
        else:
            logger.debug("App %s: %s submodule imported", self.name, submodule_name)
            setattr(self, f"{submodule_name}_module", submodule)

    def import_compliance_checks(self):
        self._import_submodule("compliance_checks")

    def import_events(self):
        self._import_submodule("events")
        events_templates_dir = os.path.join(self.path, 'events/templates')
        if os.path.isdir(events_templates_dir):
            logger.debug('App %s: found events templates dir "%s"', self.name, events_templates_dir)
            self.events_templates_dir = events_templates_dir

    def import_incidents(self):
        self._import_submodule("incidents")

    def import_provisioning(self):
        self._import_submodule("provisioning")

    # PBAC

    def import_pbac_module(self):
        self._import_submodule("pbac")

    @property
    def pbac_namespace_id(self):
        if self.pbac_module:
            return getattr(self.pbac_module, "NAMESPACE_ID")
        return "".join(w.title() for w in re.split(r"[ _]", self.name.split(".")[-1]))

    def register_legacy_perms(self):
        engine.register_app_legacy_perms(self)
