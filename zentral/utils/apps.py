from importlib import import_module
import logging
import os.path
from django.apps import AppConfig


logger = logging.getLogger('zentral.utils.apps')


class ZentralAppConfig(AppConfig):
    permission_models = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.events_module = None
        self.events_templates_dir = None
        self.incidents_module = None
        self.probes_module = None

    def ready(self):
        """
        To run some extra code when Django starts
        """
        self.import_events()
        self.import_incidents()
        self.import_probes()

    def _import_submodule(self, submodule_name):
        try:
            submodule = import_module(f"{self.name}.{submodule_name}")
        except ModuleNotFoundError:
            pass
        else:
            logger.debug("App %s: %s submodule imported", self.name, submodule_name)
            setattr(self, f"{submodule_name}_module", submodule)

    def import_events(self):
        self._import_submodule("events")
        events_templates_dir = os.path.join(self.path, 'events/templates')
        if os.path.isdir(events_templates_dir):
            logger.debug('App %s: found events templates dir "%s"', self.name, events_templates_dir)
            self.events_templates_dir = events_templates_dir

    def import_incidents(self):
        self._import_submodule("incidents")

    def import_probes(self):
        self._import_submodule("probes")
