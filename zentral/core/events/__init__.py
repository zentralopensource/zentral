from datetime import datetime
from importlib import import_module
import logging
import os.path
import uuid
from dateutil import parser
from django.core.urlresolvers import reverse
from django.utils.text import slugify
from zentral.conf import probes, settings
from zentral.contrib.inventory.models import MachineSnapshot
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
        self.request = kwargs.pop('request', None)
        self.tags = kwargs.pop('tags', [])

    def get_machine_url(self):
        try:
            tls_hostname = settings['api']['tls_hostname']
        except KeyError:
            logger.warning("Missing api.tls_hostname configuration key")
        else:
            return "{}{}".format(tls_hostname.rstrip('/'),
                                 reverse('inventory:machine',
                                         args=(self.machine_serial_number,)))

    def get_machine_snapshots(self):
        if not hasattr(self, '_cached_machine_snapshots'):
            self._cached_machine_snapshots = {}
            for ms in MachineSnapshot.objects.current().prefetch_related('groups').filter(machine__serial_number=self.machine_serial_number):
                self._cached_machine_snapshots[ms.source] = ms
        return self._cached_machine_snapshots

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
        for source, ms in self.get_machine_snapshots().items():
            ms_d = {'name': ms.get_machine_str()}
            if ms.business_unit:
                ms_d['business_unit'] = {'key': ms.business_unit.get_short_key(),
                                         'name': ms.business_unit.name}
            if ms.os_version:
                ms_d['os_version'] = str(ms.os_version)
            groups = list(ms.groups.all())
            if groups:
                ms_d['group_keys'] = [g.get_short_key() for g in groups]
                ms_d['group_names'] = [g.name for g in groups]
            if ms_d:
                key = slugify(source.name)
                if key in ms_d:
                    # TODO: earlier warning in conf check ?
                    logger.warning('Inventory source slug %s exists already', key)
                machine_d[key] = ms_d
        if machine_d:
            d['machine'] = machine_d
        return d


def _check_filter(f, d):
    for attr, val in f.items():
        event_val = d.get(attr, None)
        if isinstance(val, list) and isinstance(event_val, list):
            return all([elm in event_val for elm in val])
        elif val != event_val:
            return False
    return True


def _check_filters(probe, filter_attr, d):
    filters = probe.get(filter_attr, None)
    if not filters:
        return True
    else:
        for f in filters:
             if _check_filter(f, d):
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
            if not _check_filters(probe, 'metadata_filters', metadata):
                continue
            if _check_filters(probe, 'payload_filters', self.payload):
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
                   'machine_serial_number': self.metadata.machine_serial_number,
                   'machine_url': self.metadata.get_machine_url(),
                   'machine': self.metadata.get_machine_snapshots()}
            machine_names = {}
            for source, ms in ctx['machine'].items():
                machine_names.setdefault(ms.get_machine_str(), []).append(source.name)
            ctx['machine_names'] = machine_names
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
