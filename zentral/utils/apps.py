from importlib import import_module
import logging
import os.path
from django.apps import AppConfig
from django.utils.module_loading import module_has_submodule

logger = logging.getLogger('zentral.utils.apps')


EVENTS_MODULE_NAME = "events"
PROBES_MODULE_NAME = "probes"


class ZentralAppConfig(AppConfig):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.events_module = None
        self.events_templates_dir = None
        self.probes_module = None

    def ready(self):
        """
        To run some extra code when Django starts
        """
        self.import_events()
        self.import_probes()

    def import_events(self):
        if module_has_submodule(self.module, EVENTS_MODULE_NAME):
            events_module_name = "%s.%s" % (self.name, EVENTS_MODULE_NAME)
            self.events_module = import_module(events_module_name)
            logger.debug('Events module "%s" loaded', events_module_name)
            events_templates_dir = os.path.join(self.path, 'events/templates')
            if os.path.exists(events_templates_dir):
                self.events_templates_dir = events_templates_dir
                logger.debug('Found events templates dir "%s"', events_templates_dir)

    def import_probes(self):
        if module_has_submodule(self.module, PROBES_MODULE_NAME):
            probes_module_name = "%s.%s" % (self.name, PROBES_MODULE_NAME)
            self.probes_module = import_module(probes_module_name)
            logger.debug('Probes module "%s" imported', probes_module_name)
