import logging
from django import forms
from django.utils.translation import ugettext_lazy as _
from zentral.core.actions.backends.base import BaseAction, BaseActionForm
from zentral.contrib.jamf.api_client import APIClient, APIClientError
from zentral.contrib.jamf.models import JamfInstance

logger = logging.getLogger('zentral.contrib.jamf.actions.machine_group')


ACTION_ADD_MACHINE = "add"
ACTION_REMOVE_MACHINE = "remove"
ACTION_CHOICES = (
    (ACTION_ADD_MACHINE, _("add")),
    (ACTION_REMOVE_MACHINE, _("remove")),
)


class ActionForm(BaseActionForm):
    action = forms.ChoiceField(choices=ACTION_CHOICES, initial=ACTION_ADD_MACHINE)
    group_name = forms.CharField(label="group name")


class Action(BaseAction):
    action_form_class = ActionForm

    def trigger(self, event, probe, action_config_d):
        action = action_config_d['action']
        group_name = action_config_d['group_name']
        for ms in event.metadata.machine.snapshots:
            source = ms.source
            if source.module == 'zentral.contrib.jamf':
                device_type, jamf_id = ms.reference.split(",")
                if device_type != "computer":
                    logger.error("Only for computer devices")
                    continue
                try:
                    jamf_instance = JamfInstance.objects.get(**source.config)
                except JamfInstance.DoesNotExist:
                    logger.error("Could not find jamf instance for config %s", source.config)
                else:
                    client = APIClient(**jamf_instance.serialize())

                    if action == ACTION_ADD_MACHINE:
                        method = client.add_computer_to_group
                    elif action == ACTION_REMOVE_MACHINE:
                        method = client.remove_computer_from_group
                    else:
                        logger.error("Unknown action %s", action)
                        continue
                    try:
                        method(jamf_id, group_name)
                    except APIClientError:
                        logger.error("Could not change machine %s jamf group membership", ms.serial_number)
