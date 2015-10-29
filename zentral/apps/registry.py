from collections import OrderedDict
import threading
from zentral.core.exceptions import ImproperlyConfigured
from .config import AppConfig


class Apps(object):
    def __init__(self):
        self.app_configs = OrderedDict()
        self.all_events = {}
        self._lock = threading.Lock()

    def populate(self, apps):
        with self._lock:
            for entry, app_settings in apps.items():
                app_config = AppConfig.create(entry)
                if app_config.name in self.app_configs:
                    raise ImproperlyConfigured('App {} used more than once'.format(app_config.name))
                self.app_configs[app_config.name] = app_config
                app_config.import_events()

    def register_event(self, event_type, event_cls):
        if event_type in self.all_events:
            raise ImproperlyConfigured('Event type %s must be unique' % event_type)
        self.all_events[event_type] = event_cls

apps = Apps()
