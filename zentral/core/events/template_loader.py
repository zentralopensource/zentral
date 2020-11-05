import logging
from jinja2 import ChoiceLoader, Environment, FileSystemLoader
from jinja2.exceptions import TemplateNotFound
from django.apps import apps
from zentral.conf import user_templates_dir

logger = logging.getLogger('zentral.core.events.template_loader')


class TemplateLoader(object):
    def __init__(self, extra_lookup_dirs=None):
        self.extra_lookup_dirs = extra_lookup_dirs or []
        self._j2env = None

    def _get_j2env(self):
        if self._j2env is None:
            templates_dirs = []
            if user_templates_dir:
                templates_dirs.append(user_templates_dir)
            for app_name, app_config in apps.app_configs.items():
                app_events_template_dir = getattr(app_config, 'events_templates_dir', None)
                if app_events_template_dir:
                    templates_dirs.append(app_events_template_dir)
            templates_dirs.extend(self.extra_lookup_dirs)
            self._j2env = Environment(loader=ChoiceLoader([FileSystemLoader(d) for d in templates_dirs]),
                                      trim_blocks=True)
            logger.debug('Jinja2 env loaded')
        return self._j2env

    def load(self, event_type, part):
        j2env = self._get_j2env()
        for prefix in (event_type, 'default'):
            template_name = "{}_{}.txt".format(prefix, part)
            try:
                return j2env.get_template(template_name)
            except TemplateNotFound:
                pass
