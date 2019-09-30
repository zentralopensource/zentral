from datetime import datetime
import logging
import os.path
import re
import uuid
from dateutil import parser
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.contenttypes.models import ContentType
from django.utils.functional import cached_property
from django.utils.text import slugify
from geoip2.models import City
from zentral.contrib.inventory.models import MetaMachine
from zentral.core.queues import queues
from zentral.utils.http import user_agent_and_ip_address_from_request
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


class EventObserver(object):
    def __init__(self, hostname, vendor, type, content_type, pk):
        self.hostname = hostname
        self.vendor = vendor
        self.type = type
        self.content_type = content_type
        self.pk = pk

    @classmethod
    def deserialize(cls, observer_d):
        kwargs = {k: observer_d.get(k) for k in ("hostname", "vendor", "type", "content_type", "pk")}
        return cls(**kwargs)

    def serialize(self):
        d = {k: v for k, v in (("hostname", self.hostname),
                               ("vendor", self.vendor),
                               ("type", self.type),
                               ("content_type", self.content_type),
                               ("pk", self.pk)) if v}
        return d

    def __str__(self):
        return self.hostname or ""

    def get_object(self):
        if self.content_type and self.pk:
            try:
                app_label, model = self.content_type.split(".")
                ct = ContentType.objects.get(app_label=app_label, model=model)
                return ct.get_object_for_this_type(pk=self.pk)
            except ObjectDoesNotExist:
                pass


class EventRequestUser(object):
    user_attr_list = ["id", "username", "email",
                      "has_verification_device",
                      "is_remote", "is_superuser"]

    def __init__(self, **kwargs):
        for attr in self.user_attr_list:
            setattr(self, attr, kwargs.get(attr))

    @classmethod
    def build_from_user(cls, user):
        if user and user.is_authenticated:
            kwargs = {attr: getattr(user, attr) for attr in cls.user_attr_list}
            return cls(**kwargs)

    def serialize(self):
        d = {}
        for attr in self.user_attr_list:
            val = getattr(self, attr)
            if val is not None:
                d[attr] = val
        return d


class EventRequestGeo(object):
    geo_attr_list = ["city_name", "continent_name",
                     "country_iso_code", "country_name",
                     "location",
                     "region_iso_code", "region_name"]

    def __init__(self, **kwargs):
        for attr in self.geo_attr_list:
            setattr(self, attr, kwargs.get(attr))

    @classmethod
    def build_from_city(cls, c):
        if not isinstance(c, City):
            raise TypeError("not a geoip2.records.City object")
        kwargs = {}
        if c.city.name:
            kwargs["city_name"] = c.city.name
        if c.continent.name:
            kwargs["continent_name"] = c.continent.name
        if c.country.iso_code:
            kwargs["country_iso_code"] = c.country.iso_code
        if c.country.name:
            kwargs["country_name"] = c.country.name
        if c.location.longitude is not None and c.location.latitude is not None:
            kwargs["location"] = {"lat": c.location.latitude,
                                  "lon": c.location.longitude}
        if c.subdivisions.most_specific.iso_code:
            kwargs["region_iso_code"] = c.subdivisions.most_specific.iso_code
        if c.subdivisions.most_specific.name:
            kwargs["region_name"] = c.subdivisions.most_specific.name
        if kwargs:
            return cls(**kwargs)

    def serialize(self):
        d = {}
        for attr in self.geo_attr_list:
            val = getattr(self, attr)
            if val is not None:
                d[attr] = val
        return d

    def short_repr(self):
        return ", ".join(s for s in (self.city_name, self.country_name) if s)


class EventRequest(object):
    user_agent_str_length = 50

    def __init__(self, user_agent, ip, user=None, geo=None):
        self.user_agent = user_agent
        self.ip = ip
        self.geo = geo
        self.user = user

    @classmethod
    def build_from_request(cls, request):
        user_agent, ip = user_agent_and_ip_address_from_request(request)
        user = EventRequestUser.build_from_user(request.user)
        if user_agent or ip or user:
            return EventRequest(user_agent, ip, user=user)

    @classmethod
    def deserialize(cls, request_d):
        kwargs = {k: request_d.get(k) for k in ("user_agent", "ip")}
        geo_d = request_d.get("geo")
        if geo_d:
            kwargs["geo"] = EventRequestGeo(**geo_d)
        user_d = request_d.get("user")
        if user_d:
            kwargs["user"] = EventRequestUser(**user_d)
        return cls(**kwargs)

    def serialize(self):
        d = {k: v for k, v in (("user_agent", self.user_agent),
                               ("ip", self.ip)) if v}
        if self.geo:
            d["geo"] = self.geo.serialize()
        if self.user:
            d["user"] = self.user.serialize()
        return d

    def __str__(self):
        s_l = []
        if self.user and self.user.username:
            s_l.append(self.user.username)
        if self.ip:
            s_l.append(self.ip)
        if self.user_agent:
            user_agent = self.user_agent
            if len(user_agent) > self.user_agent_str_length:
                user_agent = "{}…".format(
                   user_agent[:self.user_agent_str_length - 1].strip()
                )
            s_l.append(user_agent)
        return " - ".join(s_l)

    def set_geo_from_city(self, city):
        self.geo = EventRequestGeo.build_from_city(city)


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
        self.machine_serial_number = kwargs.pop('machine_serial_number', None)
        if self.machine_serial_number:
            self.machine = MetaMachine(self.machine_serial_number)
        else:
            self.machine = None
        self.observer = kwargs.pop('observer', None)
        self.request = kwargs.pop('request', None)
        self.tags = kwargs.pop('tags', [])
        self.incidents = kwargs.pop('incidents', [])

    @classmethod
    def deserialize(cls, event_d_metadata):
        kwargs = event_d_metadata.copy()
        kwargs['event_type'] = kwargs.pop('type')
        kwargs['uuid'] = kwargs.pop('id')
        observer_d = kwargs.pop('observer', None)
        if observer_d:
            kwargs['observer'] = EventObserver.deserialize(observer_d)
        request_d = kwargs.pop('request', None)
        if request_d:
            kwargs['request'] = EventRequest.deserialize(request_d)
        return cls(**kwargs)

    def serialize_machine(self):
        machine_d_cache_key = "machine_d_{}".format(self.machine.get_urlsafe_serial_number())
        machine_d = cache.get(machine_d_cache_key)
        if not machine_d:
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
            cache.set(machine_d_cache_key, machine_d, 60)  # TODO: Hard coded timeout value
        return machine_d

    def serialize(self, machine_metadata=True):
        d = {'created_at': self.created_at.isoformat(),
             'id': str(self.uuid),
             'index': self.index,
             'type': self.event_type,
             }
        if self.observer:
            d['observer'] = self.observer.serialize()
        if self.request:
            d['request'] = self.request.serialize()
        if self.tags:
            d['tags'] = self.tags
        if self.incidents:
            d['incidents'] = self.incidents
        if self.machine_serial_number:
            d['machine_serial_number'] = self.machine_serial_number
        if not machine_metadata or not self.machine:
            return d
        machine_d = self.serialize_machine()
        if machine_d:
            d['machine'] = machine_d
        return d

    def add_incident(self, incident):
        self.incidents.append(incident.serialize_for_event_metadata())


class BaseEvent(object):
    event_type = "base"
    tags = []
    heartbeat_timeout = None
    payload_aggregations = []

    @classmethod
    def build_from_machine_request_payloads(cls, msn, ua, ip, payloads, get_created_at=None, observer=None):
        if ua or ip:
            request = EventRequest(ua, ip)
        else:
            request = None
        if observer:
            observer = EventObserver.deserialize(observer)
        metadata = EventMetadata(cls.event_type,
                                 machine_serial_number=msn,
                                 observer=observer,
                                 request=request,
                                 tags=cls.tags)
        for index, payload in enumerate(payloads):
            metadata.index = index
            if get_created_at:
                try:
                    metadata.created_at = get_created_at(payload)
                except Exception:
                    logger.exception("Could not extract created_at from payload")
            yield cls(metadata, payload)

    @classmethod
    def post_machine_request_payloads(cls, msn, user_agent, ip, payloads, get_created_at=None, observer=None):
        for event in cls.build_from_machine_request_payloads(msn, user_agent, ip, payloads, get_created_at, observer):
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
        return {'event': self,
                'metadata': self.metadata,
                'payload': self.payload,
                'machine': self.metadata.machine}

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

    # aggregations

    @classmethod
    def get_payload_aggregations(cls):
        for _, val in cls.payload_aggregations:
            if "event_type" not in val:
                val["event_type"] = cls.event_type
        return cls.payload_aggregations


register_event_type(BaseEvent)


# Zentral Commands


class CommandEvent(BaseEvent):
    COMMAND_RE = re.compile(r"^zentral\$(?P<command>[a-zA-Z\-_ ]+)"
                            r"(?P<serial_numbers>(?:\$[a-zA-Z0-9\-_]+)+)"
                            r"(?P<args>(?:#[a-zA-Z0-9\-_ ]+)+)?$")
    event_type = "zentral_command"
    tags = ["zentral"]


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
                                             tags=CommandEvent.tags + tags)
                    event = CommandEvent(metadata, payload.copy())
                    event.post()


# Zentral machine conflict
# When the machine posting the data is not the machine which is configured


class MachineConflictEvent(BaseEvent):
    event_type = "zentral_machine_conflict"
    tags = ["zentral"]
    payload_aggregations = [
        ("module", {"type": "terms", "bucket_number": 10, "label": "Modules"}),
        ("enrollment_serial_number", {"type": "terms", "bucket_number": 10, "label": "Duplicated serial numbers"}),
    ]


register_event_type(MachineConflictEvent)


def post_machine_conflict_event(request, module, reported_serial_number, enrollment_serial_number, machine_info):
    metadata = EventMetadata(MachineConflictEvent.event_type,
                             machine_serial_number=reported_serial_number,
                             tags=MachineConflictEvent.tags,
                             request=EventRequest.build_from_request(request))
    payload = {"module": module,
               "reported_machine_info": machine_info,
               "enrollment_serial_number": enrollment_serial_number}
    event = MachineConflictEvent(metadata, payload)
    event.post()
