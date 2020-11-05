from importlib import import_module
from zentral.conf import settings

__all__ = ['queues']


def get_queues_instance(queue_settings):
    module_path = queue_settings.get('backend')
    if not module_path:
        return
    class_name = "EventQueues"
    module = import_module(module_path)
    return getattr(module, class_name)(queue_settings)


def get_queues(settings):
    queues_settings = settings.get('queues', {}).copy()
    queues_settings['stores'] = list(settings.get('stores', {}).keys())
    return get_queues_instance(queues_settings)


queues = get_queues(settings)
