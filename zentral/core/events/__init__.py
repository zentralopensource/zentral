from datetime import datetime
from importlib import import_module
import logging
import os.path
import uuid
from dateutil import parser
from zentral.apps import apps
from zentral.conf import settings
from zentral.core.queues import queues
from zentral.core.templates import TemplateLoader

logger = logging.getLogger('zentral.core.events')

# Event Middlewares


class EventHandler(object):
    def __init__(self):
        self.processors = None

    def _load_middlewares(self):
        self.processors = []
        for entry in settings.get('middlewares', []):
            mw_modulename, _, mw_classname = entry.rpartition('.')
            mw_module = import_module(mw_modulename)
            mw_class = getattr(mw_module, mw_classname)
            self.processors.append(mw_class().process_event)

    def apply_middlewares(self, event):
        if self.processors is None:
            self._load_middlewares()
        for processor in self.processors:
            processor(event)

event_handler = EventHandler()

# Event deserializer


def register_event_type(event_cls):
    """Register event class for an event type.

    event_type must be unique in the zentral configuration.
    """
    event_type = event_cls.event_type
    apps.register_event(event_type, event_cls)


def event_cls_from_type(event_type):
    try:
        return apps.all_events[event_type]
    except KeyError:
        logger.error('Unknown event type %s' % event_type)
        return BaseEvent


def event_from_event_d(event_d):
    """Build event object from event dictionary."""
    event_type = event_d['_zentral']['type']
    event_cls = event_cls_from_type(event_type)
    event = event_cls.deserialize(event_d)
    event_handler.apply_middlewares(event)
    return event

# Event Base Classes

# Notification rendering

template_loader = TemplateLoader([os.path.join(os.path.dirname(__file__), 'templates')])


def render_notification_part(ctx, event_type, part):
    template_name = "{}_{}.txt".format(event_type, part)
    template = template_loader.load(template_name)
    if template:
        return template.render(ctx)
    else:
        msg = 'Missing template {}'.format(template_name)
        logger.error(msg)
        return msg

# Classes


class EventRequest(object):
    def __init__(self, user_agent, ip):
        self.user_agent = user_agent
        self.ip = ip

    def serialize(self):
        return {'user_agent': self.user_agent,
                'ip': self.ip}


class EventMetadata(object):
    def __init__(self, event_type, **kwargs):
        self.event_type = event_type
        self.uuid = kwargs.pop('uuid', uuid.uuid4())
        if isinstance(self.uuid, str):
            self.uuid = uuid.UUID(self.uuid)
        self.index = int(kwargs.pop('index', 0))
        self.created_at = kwargs.pop('created_at', datetime.utcnow())
        if isinstance(self.created_at, str):
            self.created_at = parser.parse(self.created_at)
        self.machine_serial_number = kwargs.pop('machine_serial_number')
        self.request = kwargs.pop('request', None)

    @classmethod
    def deserialize(cls, event_d_metadata):
        kwargs = event_d_metadata.copy()
        kwargs['event_type'] = kwargs.pop('type')
        kwargs['uuid'] = kwargs.pop('id')
        request_d = kwargs.pop('request', None)
        if request_d:
            kwargs['request'] = EventRequest(**request_d)
        return cls(**kwargs)

    def serialize(self):
        d = {'created_at': self.created_at.isoformat(),
             'id': str(self.uuid),
             'index': self.index,
             'type': self.event_type,
             'machine_serial_number': self.machine_serial_number}
        if self.request:
            d['request'] = self.request.serialize()
        return d


class BaseEvent(object):
    event_type = "base"

    def __init__(self, metadata, payload):
        self.metadata = metadata
        self.payload = payload
        self._notification_context = None
        self._notification_subject = None
        self._notification_body = None

    def _key(self):
        return (self.event_type, self.metadata.uuid, self.metadata.index)

    def __eq__(self, other):
        return self._key() == other._key()

    @classmethod
    def deserialize(cls, event_d):
        payload = event_d.copy()
        metadata = EventMetadata.deserialize(payload.pop('_zentral'))
        return cls(metadata, payload)

    def serialize(self):
        event_d = self.payload.copy()
        event_d['_zentral'] = self.metadata.serialize()
        return event_d

    def post(self):
        queues.post_event(self)

    def is_filtered_out(self):
        return False

    # notification methods

    def _get_extra_context(self):
        # to be implemented in the sub classes
        return {}

    def get_notification_context(self):
        if self._notification_context is None:
            ctx = {'event_id': self.metadata.uuid,
                   'machine': {'serial_number': self.metadata.machine_serial_number}}
            ctx.update(self._get_extra_context())
            self._notification_context = ctx
        return self._notification_context

    def get_notification_subject(self):
        if self._notification_subject is None:
            ctx = self.get_notification_context()
            self._notification_subject = render_notification_part(ctx, self.event_type, 'subject')
        return self._notification_subject

    def get_notification_body(self):
        if self._notification_body is None:
            ctx = self.get_notification_context()
            self._notification_body = render_notification_part(ctx, self.event_type, 'body')
        return self._notification_body
