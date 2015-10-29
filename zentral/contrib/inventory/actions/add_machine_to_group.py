import logging
from zentral.contrib.inventory import inventory

logger = logging.getLogger('zentral.contrib.inventory.actions.add_machine_to_group')


class Action(object):
    def __init__(self, config_d):
        self.config_d = config_d

    def trigger(self, event_d, action_config_d, probe=None, query_conf=None):
        group_name = action_config_d['group_name']
        try:
            inventory.add_machine_to_group(event_d['_zentral']['machine'], group_name)
        except:
            logger.exception('Could not add machine to group %s', group_name)
