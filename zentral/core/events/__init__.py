from datetime import datetime
import logging
import os.path
import uuid
from dateutil import parser
from django.utils.text import slugify
from zentral.conf import probes
from zentral.contrib.inventory.models import MetaMachine
from zentral.core.exceptions import ImproperlyConfigured
from zentral.core.queues import queues
from .template_loader import TemplateLoader

logger = logging.getLogger('zentral.core.events')


# Event deserializer

# The event_types are populated by "register_event_type"
# "register_event_type" is called after an event class definition in an zentral contrib app events module.
# the events modules of the different contrib apps are loaded during the Django setup.
# Zentral contrib apps have ZentralAppConfig instances that try to load an app's event module
# when they are ready (thus triggering the "register_event_type" calls present in these modules).
#
# see zentral.utils.apps.ZentralAppConfig

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


def event_cls_from_type(event_type):
    try:
        return event_types[event_type]
    except KeyError:
        logger.error('Unknown event type "%s"', event_type)
        return BaseEvent


def event_from_event_d(event_d):
    """Build event object from event dictionary."""
    event_type = event_d['_zentral']['type']
    event_cls = event_cls_from_type(event_type)
    event = event_cls.deserialize(event_d)
    return event

# Event Base Classes

# Notification rendering

template_loader = TemplateLoader([os.path.join(os.path.dirname(__file__), 'templates')])


def render_notification_part(ctx, event_type, part):
    template = template_loader.load(event_type, part)
    if template:
        return template.render(ctx)
    else:
        msg = 'Missing template event_type: {} part: {}'.format(event_type, part)
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
        self.machine = MetaMachine(self.machine_serial_number)
        self.request = kwargs.pop('request', None)
        self.tags = kwargs.pop('tags', [])

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
             'machine_serial_number': self.machine_serial_number,
             }
        if self.request:
            d['request'] = self.request.serialize()
        if self.tags:
            d['tags'] = self.tags
        machine_d = {}
        for ms in self.machine.snapshots:
            source = ms.source
            ms_d = {'name': ms.get_machine_str()}
            if ms.business_unit:
                if not ms.business_unit.is_api_enrollment_business_unit():
                    ms_d['business_unit'] = {'reference': ms.business_unit.reference,
                                             'key': ms.business_unit.get_short_key(),
                                             'name': ms.business_unit.name}
            if ms.os_version:
                ms_d['os_version'] = str(ms.os_version)
            for group in ms.groups.all():
                ms_d.set_default('groups', []).append({'reference': group.reference,
                                                       'key': group.get_short_key(),
                                                       'name': group.name})
            key = slugify(source.name)
            if key in ms_d:
                # TODO: earlier warning in conf check ?
                logger.warning('Inventory source slug %s exists already', key)
            machine_d[key] = ms_d
        for tag in self.machine.tags():
            machine_d.setdefault('tags', []).append({'id': tag.id,
                                                     'name': tag.name})
        for meta_business_unit in self.machine.meta_business_units():
            machine_d.setdefault('meta_business_units', []).append({
                'name': meta_business_unit.name,
                'id': meta_business_unit.id
            })
        if machine_d:
            d['machine'] = machine_d
        return d


def _test_pass_filter_item(filter_attr, filter_val, val):
    """Evaluate a value against a filter item."""
    # TODO: __icontains for partial case insensitive matches (verify that test_probe_event_type is still valid!)
    if isinstance(filter_val, list) and isinstance(val, list):
        return all([elm in val for elm in filter_val])
    elif filter_val != val:
        return False
    else:
        return True


def _test_pass_filter(f, d):
    """Iterate on all the filter items and evaluate the dictionary against them.

       Bookean AND. The dictionary must match all filter items."""
    for filter_attr, filter_val in f.items():
        # TODO: . separated filter_attr for deeper level dictionary attributes
        val = d.get(filter_attr, None)
        test = _test_pass_filter_item(filter_attr, filter_val, val)
        if not test:
            # AND - all items in a filter must match
            return False
    return True


def _test_pass_filters(filters, d):
    """Iterate on all the filters, and evaluate the dictionary against them.

       Boolean OR. The dictionary must match at least one of the filters."""
    if not filters:
        # No filters, it's always a match
        return True
    else:
        for f in filters:
            if _test_pass_filter(f, d):
                # OR - one of the filters must match
                return True
        return False


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

    def extra_probe_checks(self, probe):
        return True

    def get_probes(self):
        l = []
        metadata = self.metadata.serialize()
        for probe in probes.values():
            if not self.extra_probe_checks(probe):
                continue
            if not _test_pass_filters(probe.get('metadata_filters', None), metadata):
                continue
            if _test_pass_filters(probe.get('payload_filters', None), self.payload):
                l.append(probe)
        return l

    # notification methods

    def _get_extra_context(self):
        # to be implemented in the sub classes
        return {}

    def get_notification_context(self, probe):
        if self._notification_context is None:
            ctx = {'event_id': self.metadata.uuid,
                   'created_at': self.metadata.created_at,
                   'payload': self.payload,
                   'probe': probe,
                   'machine': self.metadata.machine,
                   'machine_serial_number': self.metadata.machine.serial_number,
                   'machine_snapshots': self.metadata.machine.snapshots,
                   'machine_url': self.metadata.machine.get_url()}
            ctx.update(self._get_extra_context())
            self._notification_context = ctx
        return self._notification_context

    def get_notification_subject(self, probe):
        if self._notification_subject is None:
            ctx = self.get_notification_context(probe)
            self._notification_subject = render_notification_part(ctx, self.event_type, 'subject')
        return self._notification_subject

    def get_notification_body(self, probe):
        if self._notification_body is None:
            ctx = self.get_notification_context(probe)
            self._notification_body = render_notification_part(ctx, self.event_type, 'body')
        return self._notification_body
