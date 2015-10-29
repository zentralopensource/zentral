from importlib import import_module
from zentral.conf import settings

__all__ = ['actions']


def get_action_class(module_path):
    class_name = "Action"
    module = import_module(module_path)
    return getattr(module, class_name)


def get_actions(settings):
    actions = {}
    for action_name, action_conf in settings['actions'].items():
        action_conf = action_conf.copy()
        action_conf['action_name'] = action_name
        action_class = get_action_class(action_conf.pop('backend'))
        actions[action_name] = action_class(action_conf)
    return actions

actions = get_actions(settings)
