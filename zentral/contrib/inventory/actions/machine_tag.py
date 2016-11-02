import logging
from django.db.models import Q
from django import forms
from django.utils.text import slugify
from django.utils.translation import ugettext_lazy as _
from zentral.core.actions.backends.base import BaseAction, BaseActionForm
from zentral.contrib.inventory.models import Tag, MachineTag

logger = logging.getLogger('zentral.contrib.inventory.actions.machine_tag')

ACTION_ADD_TAG = "add"
ACTION_REMOVE_TAG = "remove"
ACTION_CHOICES = (
  (ACTION_ADD_TAG, _("add")),
  (ACTION_REMOVE_TAG, _("remove")),
)


class ActionForm(BaseActionForm):
    action = forms.ChoiceField(choices=ACTION_CHOICES, initial=ACTION_ADD_TAG)
    tags = forms.ModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)
    tags_from_event_payload_attr = forms.CharField(label="Event payload attribute",
                                                   required=False,
                                                   help_text="Attribute of the event payload containing the tags")

    def clean_tags(self):
        # store list of tag ids in the probe body
        tags = self.cleaned_data.get("tags") or []
        return [t.id for t in tags]

    def clean(self):
        cleaned_data = self.cleaned_data
        tags = cleaned_data.get("tags")
        tags_from_event_payload_attr = cleaned_data.get("tags_from_event_payload_attr")
        if not tags and not tags_from_event_payload_attr:
            raise forms.ValidationError("both tags and event payload attribute empty")
        return cleaned_data


class Action(BaseAction):
    action_form_class = ActionForm
    probe_config_template_name = "inventory/_machine_tag_action_probe_config.html"

    @staticmethod
    def get_probe_context_action_config_d(action_config_d):
        """prepare a dict for the display of the action_config_d in the probe view"""
        return {'action': action_config_d['action'],
                'tags': sorted(Tag.objects.filter(id__in=action_config_d.get('tags', [])),
                               key=lambda t: t.name),
                'tags_from_event_payload_attr': action_config_d.get('tags_from_event_payload_attr', None)}

    def get_tags(self, event, probe, action_config_d):
        tags = None
        if 'tags' in action_config_d:
            tags = action_config_d['tags']
        elif 'tags_from_event_payload_attr' in action_config_d:
            tags = event.payload.get(action_config_d['tags_from_event_payload_attr'], [])
        if not tags:
            logger.error("No tags or tags_from_event_payload_attr in machine tag action %s of probe %s",
                         self.name, probe.name)
            return
        tag_id_list = []
        tag_slug_list = []
        if isinstance(tags, (str, int)):
            tags = [tags]
        if isinstance(tags, list):
            for t in tags:
                if isinstance(t, int):
                    tag_id_list.append(t)
                elif isinstance(t, str):
                    try:
                        tag_id = int(t)
                    except ValueError:
                        tag_slug_list.append(slugify(t))
                    else:
                        tag_id_list.append(tag_id)
        if not tag_id_list and not tag_slug_list:
            logger.error("tags must be a list of tag id or tag name in machine tag action %s of probe %s",
                         self.name, probe.name)
            return
        tags_qs = Tag.objects.distinct().filter(Q(pk__in=tag_id_list) | Q(slug__in=tag_slug_list))
        if tags_qs.count() < (len(tag_id_list) + len(tag_slug_list)):
            logger.error("Some tags could not be found or are duplicated in machine tag action %s of probe %s",
                         self.name, probe.name)
        return tags_qs

    def trigger(self, event, probe, action_config_d):
        msn = event.metadata.machine_serial_number
        tags = self.get_tags(event, probe, action_config_d)
        if not tags:
            return
        for tag in tags:
            action = action_config_d['action']
            if action == ACTION_ADD_TAG:
                MachineTag.objects.get_or_create(serial_number=msn, tag=tag)
            elif action == ACTION_REMOVE_TAG:
                MachineTag.objects.filter(serial_number=msn, tag=tag).delete()
            else:
                raise ValueError("Unknown action '%s' in machine tag action %s of probe %s",
                                 action, self.name, probe.name)
