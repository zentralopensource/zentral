import logging
from django import forms
from zentral.core.actions.backends.base import BaseAction, BaseActionForm
from zentral.contrib.jamf.api_client import (INVENTORY_DISPLAY_CHOICES, INVENTORY_DISPLAY_GENERAL,
                                             APIClient, APIClientError)
from zentral.contrib.jamf.models import JamfInstance

logger = logging.getLogger('zentral.contrib.jamf.actions.computer_extension_attribute')


class ActionForm(BaseActionForm):
    extension_attribute_name = forms.CharField()
    inventory_display = forms.ChoiceField(choices=INVENTORY_DISPLAY_CHOICES, initial=INVENTORY_DISPLAY_GENERAL)
    value = forms.CharField()


class Action(BaseAction):
    action_form_class = ActionForm

    def trigger(self, event, probe, action_config_d):
        name = action_config_d['extension_attribute_name']
        inventory_display = action_config_d["inventory_display"]
        value = action_config_d["value"]
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
                    try:
                        client.update_text_computer_extension_attribute(jamf_id, name, inventory_display, value)
                    except APIClientError:
                        logger.exception("Could not update machine %s computer extension attribute", ms.serial_number)
