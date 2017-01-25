from importlib import import_module
from zentral.conf import settings

__all__ = ['queues']


def get_queues_class(settings):
    module_path = settings['queues']['backend']
    class_name = "EventQueues"
    module = import_module(module_path)
    return getattr(module, class_name)


def get_queues(settings):
    queues_settings = settings['queues'].copy()
    queues_settings['stores'] = list(settings['stores'].keys())
    return get_queues_class(settings)(queues_settings)


queues = get_queues(settings)
