from datetime import datetime
import logging
import os.path
import re
import uuid
from dateutil import parser
from django.utils.functional import cached_property
from django.utils.text import slugify
from zentral.contrib.inventory.models import MetaMachine
from zentral.core.queues import queues
from .template_loader import TemplateLoader
from . import register_event_type

logger = logging.getLogger('zentral.core.events.base')


template_loader = TemplateLoader([os.path.join(os.path.dirname(__file__), 'templates')])


def render_notification_part(ctx, event_type, part):
    template = template_loader.load(event_type, part)
    if template:
        return template.render(ctx)
    else:
        msg = 'Missing template event_type: {} part: {}'.format(event_type, part)
        logger.error(msg)
        return msg


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
        self.created_at = kwargs.pop('created_at', None)
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        elif isinstance(self.created_at, str):
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

    def serialize(self, machine_metadata=True):
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
        if not machine_metadata:
            return d
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
                ms_d.setdefault('groups', []).append({'reference': group.reference,
                                                      'key': group.get_short_key(),
                                                      'name': group.name})
            key = slugify(source.name)
            if key in ms_d:
                # TODO: earlier warning in conf check ?
                logger.warning('Inventory source slug %s exists already', key)
            machine_d[key] = ms_d
        for tag in self.machine.tags:
            machine_d.setdefault('tags', []).append({'id': tag.id,
                                                     'name': tag.name})
        for meta_business_unit in self.machine.meta_business_units:
            machine_d.setdefault('meta_business_units', []).append({
                'name': meta_business_unit.name,
                'id': meta_business_unit.id
            })
        if self.machine.platform:
            machine_d['platform'] = self.machine.platform
        if self.machine.type:
            machine_d['type'] = self.machine.type
        if machine_d:
            d['machine'] = machine_d
        return d


class BaseEvent(object):
    event_type = "base"
    tags = []

    @classmethod
    def build_from_machine_request_payloads(cls, msn, ua, ip, payloads):
        metadata = EventMetadata(cls.event_type,
                                 machine_serial_number=msn,
                                 request=EventRequest(ua, ip),
                                 tags=cls.tags)
        for index, payload in enumerate(payloads):
            metadata.index = index
            yield cls(metadata, payload)

    @classmethod
    def post_machine_request_payloads(cls, msn, user_agent, ip, payloads):
        for event in cls.build_from_machine_request_payloads(msn, user_agent, ip, payloads):
            event.post()

    def __init__(self, metadata, payload):
        self.metadata = metadata
        self.payload = payload

    def _key(self):
        return (self.event_type, self.metadata.uuid, self.metadata.index)

    def __eq__(self, other):
        return self._key() == other._key()

    @classmethod
    def get_event_type_display(cls):
        return cls.event_type.replace("_", " ")

    def __str__(self):
        return self.get_event_type_display()

    @classmethod
    def get_app_display(cls):
        module = cls.__module__
        if module.startswith("zentral.core"):
            return "Zentral"
        else:
            try:
                return module.split(".")[-2].capitalize()
            except IndexError:
                return module

    @classmethod
    def deserialize(cls, event_d):
        payload = event_d.copy()
        metadata = EventMetadata.deserialize(payload.pop('_zentral'))
        return cls(metadata, payload)

    def serialize(self, machine_metadata=True):
        event_d = self.payload.copy()
        event_d['_zentral'] = self.metadata.serialize(machine_metadata)
        return event_d

    def post(self):
        queues.post_event(self)

    def extra_probe_checks(self, probe):
        return True

    # notification methods

    @cached_property
    def base_notification_context(self):
        return {'event_id': self.metadata.uuid,
                'created_at': self.metadata.created_at,
                'payload': self.payload,
                'machine': self.metadata.machine,
                'machine_serial_number': self.metadata.machine.serial_number,
                'machine_snapshots': self.metadata.machine.snapshots,
                'machine_url': self.metadata.machine.get_url()}

    def get_notification_context(self, probe):
        ctx = self.base_notification_context.copy()
        ctx["probe"] = probe
        return ctx

    def get_notification_subject(self, probe):
        ctx = self.get_notification_context(probe)
        return render_notification_part(ctx, self.event_type, 'subject')

    def get_notification_body(self, probe):
        ctx = self.get_notification_context(probe)
        return render_notification_part(ctx, self.event_type, 'body')


register_event_type(BaseEvent)


# Zentral Commands


class CommandEvent(BaseEvent):
    COMMAND_RE = re.compile(r"^zentral\$(?P<command>[a-zA-Z\-_ ]+)"
                            "(?P<serial_numbers>(?:\$[a-zA-Z0-9\-_]+)+)"
                            "(?P<args>(?:#[a-zA-Z0-9\-_ ]+)+)?$")
    event_type = "zentral_command"


register_event_type(CommandEvent)


def post_command_events(message, source, tags):
    if not message:
        return
    for line in message.splitlines():
        line = line.strip()
        m = CommandEvent.COMMAND_RE.match(line)
        if m:
            payload = {'command': m.group('command'),
                       'source': source}
            args = m.group('args')
            if args:
                payload['args'] = [arg for arg in args.split('#') if arg]
            for serial_number in m.group('serial_numbers').split('$'):
                if serial_number:
                    metadata = EventMetadata(CommandEvent.event_type,
                                             machine_serial_number=serial_number,
                                             tags=tags)
                    event = CommandEvent(metadata, payload.copy())
                    event.post()
