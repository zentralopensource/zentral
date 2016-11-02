import logging
from zentral.core.exceptions import ImproperlyConfigured

logger = logging.getLogger('zentral.core.events')


# Event deserializer

# The event_types are populated by "register_event_type"
# "register_event_type" is called after an event class definition in an zentral contrib app events module.
# the events modules of the different contrib apps are loaded during the Django setup.
# Zentral contrib apps have ZentralAppConfig instances that try to load an app's event module
# when they are ready (thus triggering the "register_event_type" calls present in these modules).
#
# see zentral.utils.apps.ZentralAppConfig

event_tags = {}

event_types = {}


def register_event_type(event_cls):
    """
    Register event class for an event type.

    event_type must be unique in the zentral configuration.
    """
    event_type = event_cls.event_type
    if event_type in event_types:
        raise ImproperlyConfigured('Event type {} already registered'.format(event_type))
    logger.debug('Event type "%s" registered', event_type)
    event_types[event_type] = event_cls
    for tag in event_cls.tags:
        event_tags.setdefault(tag, []).append(event_cls)


def event_cls_from_type(event_type):
    try:
        return event_types[event_type]
    except KeyError:
        logger.error('Unknown event type "%s"', event_type)
        # BaseEvent registered in .base.py
        return event_types["base"]


def event_from_event_d(event_d):
    """Build event object from event dictionary."""
    event_type = event_d['_zentral']['type']
    event_cls = event_cls_from_type(event_type)
    event = event_cls.deserialize(event_d)
    return event
