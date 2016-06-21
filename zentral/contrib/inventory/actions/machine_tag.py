import logging
from django.db.models import Q
from django.utils.text import slugify
from zentral.core.actions.backends.base import BaseAction
from zentral.contrib.inventory.models import Tag, MachineTag

logger = logging.getLogger('zentral.contrib.inventory.actions.machine_tag')


class Action(BaseAction):
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
            if action == 'add':
                MachineTag.objects.get_or_create(serial_number=msn, tag=tag)
            elif action == 'remove':
                MachineTag.objects.filter(serial_number=msn, tag=tag).delete()
            else:
                raise ValueError("Unknown action '%s' in machine tag action %s of probe %s",
                                 action, self.name, probe.name)
