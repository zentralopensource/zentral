import logging
from zentral.contrib.inventory.clients import clients

logger = logging.getLogger('zentral.contrib.inventory.actions.add_machine_to_group')


class Action(object):
    def __init__(self, config_d):
        self.config_d = config_d

    def trigger(self, event, probe, action_config_d):
        group_name = action_config_d['group_name']
        machine = event.metadata.get_machine_snapshots()
        for client in clients:
            for source, ms in machine.items():
                if source.module == client.source['module'] and source.config == client.source['config']:
                    try:
                        client.add_machine_to_group(ms, group_name)
                    except:
                        logger.exception('Could not add machine to group %s with client %s',
                                         group_name, client.name)
                    break
            else:
                logger.exception('No machine snapshot for inventort client %s/%s', client.source, client.name)
