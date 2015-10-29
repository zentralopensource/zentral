import os.path
from jinja2 import ChoiceLoader, Environment, FileSystemLoader
from zentral.conf import user_templates_dir


class TemplateLoader(object):
    def __init__(self, extra_lookup_dirs=None):
        self.extra_lookup_dirs = extra_lookup_dirs or []
        self._j2env = None

    def _get_j2env(self):
        if self._j2env is None:
            templates_dirs = [user_templates_dir]
            from zentral.apps import apps
            for app_name, app_config in apps.app_configs.items():
                templates_dirs.append(os.path.join(app_config.path, 'events/templates'))
            templates_dirs.extend(self.extra_lookup_dirs)
            self._j2env = Environment(loader=ChoiceLoader([FileSystemLoader(d) for d in templates_dirs]),
                                      trim_blocks=True)
        return self._j2env

    def load(self, template_name):
        j2env = self._get_j2env()
        return j2env.get_template(template_name)
