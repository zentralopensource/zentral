import logging
from django import forms
from zentral.core.actions.backends.base import BaseAction, BaseActionForm
from zentral.contrib.inventory.clients import clients

logger = logging.getLogger('zentral.contrib.inventory.actions.add_machine_to_group')


class ActionForm(BaseActionForm):
    group_name = forms.CharField(label="group name")


class Action(BaseAction):
    action_form_class = ActionForm

    def trigger(self, event, probe, action_config_d):
        group_name = action_config_d['group_name']
        for client in clients:
            for ms in event.metadata.machine.snapshots:
                source = ms.source
                if source.module == client.source['module'] and source.config == client.source['config']:
                    try:
                        client.add_machine_to_group(ms, group_name)
                    except Exception:
                        logger.exception('Could not add machine to group %s with client %s',
                                         group_name, client.name)
                    break
            else:
                logger.exception('No machine snapshot for inventort client %s/%s', client.source, client.name)
