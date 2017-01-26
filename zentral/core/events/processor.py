import logging
from . import event_from_event_d
from zentral.core.probes.conf import all_probes

logger = logging.getLogger('zentral.core.events.processor')


class EventProcessor(object):
    def process(self, event):
        if isinstance(event, dict):
            event = event_from_event_d(event)
        for probe in all_probes.event_filtered(event):
            for action, action_config_d in probe.actions:
                try:
                    action.trigger(event, probe, action_config_d)
                except:
                    logger.exception("Could not trigger action %s", action.name)
