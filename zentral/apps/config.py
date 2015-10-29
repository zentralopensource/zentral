from importlib import import_module
import os.path
from zentral.core.exceptions import ImproperlyConfigured


class AppConfig(object):
    def __init__(self, app_name, app_module):
        self.name = app_name
        self.module = app_module
        self.path = self._path_from_module(app_module)
        self.events_module = None

    @classmethod
    def create(cls, entry):
        app_module = import_module(entry)
        return cls(entry, app_module)

    def import_events(self):
        self.events_module = import_module('.events', self.name)

    @staticmethod
    def _path_from_module(module):
        # see django.apps.config. Shortcut. TODO: cleanup
        paths = getattr(module, '__path__', [])
        if len(paths) != 1:
            filename = getattr(module, '__file__', None)
            if filename is not None:
                paths = [os.path.dirname(filename)]
        if len(paths) != 1:
            raise ImproperlyConfigured('Could not determine path for module %r' % module)
        return paths[0]
