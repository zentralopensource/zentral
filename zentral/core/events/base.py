from datetime import datetime
from enum import Enum
import logging
import os.path
import re
import uuid
import weakref
from dateutil import parser
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.contenttypes.models import ContentType
from django.utils.functional import cached_property
from geoip2.models import City
from rest_framework.authentication import TokenAuthentication
from zentral.contrib.inventory.models import MetaMachine
from zentral.core.incidents.models import IncidentUpdate
from zentral.core.probes.conf import all_probes_dict
from zentral.core.queues import queues
from zentral.utils.http import user_agent_and_ip_address_from_request
from zentral.utils.text import decode_args, encode_args
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
    def __init__(self, hostname, vendor, product, type, content_type, pk):
        self.hostname = hostname
        self.vendor = vendor
        self.product = product
        self.type = type
        self.content_type = content_type
        self.pk = pk

    @classmethod
    def deserialize(cls, observer_d):
        kwargs = {k: observer_d.get(k) for k in ("hostname", "vendor", "product", "type", "content_type", "pk")}
        return cls(**kwargs)

    def serialize(self):
        d = {k: v for k, v in (("hostname", self.hostname),
                               ("vendor", self.vendor),
                               ("product", self.product),
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
                ct = ContentType.objects.get_by_natural_key(app_label, model)
                return ct.get_object_for_this_type(pk=self.pk)
            except ObjectDoesNotExist:
                pass


class EventRequestUser(object):
    attr_list = ["id", "username", "email",
                 "is_remote", "is_service_account", "is_superuser",
                 "session"]

    def __init__(self, **kwargs):
        for attr in self.attr_list:
            setattr(self, attr, kwargs.get(attr))

    @classmethod
    def build_from_request(cls, request):
        user = request.user
        if user and user.is_authenticated:
            kwargs = {attr: getattr(user, attr) for attr in cls.attr_list if attr != "session"}
            session_d = kwargs.setdefault("session", {})
            drf_authenticator = getattr(request, "successful_authenticator", None)
            token_authenticated = isinstance(drf_authenticator, TokenAuthentication)
            session_d["token_authenticated"] = token_authenticated
            if token_authenticated:
                session_d["is_remote"] = False
                session_d["mfa_authenticated"] = False
            else:
                # session
                session = request.session
                # session expiry
                seabc = session.get_expire_at_browser_close()
                session_d["expire_at_browser_close"] = seabc
                if not seabc:
                    session_d["expiry_age"] = session.get_expiry_age()
                # realm session?
                # set via realms middleware, but absent if logout from test client for example
                ras = getattr(request, "realm_authentication_session", None)
                if ras and ras.is_remote:
                    session_d.update({
                        "is_remote": True,
                        "realm_authentication_session_pk": ras.pk,
                        "realm_user_pk": ras.user.pk,
                        "realm": {
                            "pk": ras.realm.pk,
                            "name": ras.realm.name
                        }
                    })
                else:
                    # mfa?
                    session_d["is_remote"] = False
                    if session.get("mfa_authenticated"):
                        session_d["mfa_authenticated"] = True
                    else:
                        session_d["mfa_authenticated"] = False
            return cls(**kwargs)

    def serialize(self):
        d = {}
        for attr in self.attr_list:
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

    def __init__(self, user_agent, ip, user=None, geo=None, method=None, path=None):
        self.user_agent = user_agent
        self.ip = ip
        self.geo = geo
        self.user = user
        self.method = method
        self.path = path

    @classmethod
    def build_from_request(cls, request):
        user_agent, ip = user_agent_and_ip_address_from_request(request)
        user = EventRequestUser.build_from_request(request)
        method = request.method
        path = request.get_full_path()
        return EventRequest(
            user_agent, ip,
            user=user, method=method, path=path
        )

    @classmethod
    def deserialize(cls, request_d):
        kwargs = {k: request_d.get(k) for k in ("user_agent", "ip", "method", "path")}
        geo_d = request_d.get("geo")
        if geo_d:
            kwargs["geo"] = EventRequestGeo(**geo_d)
        user_d = request_d.get("user")
        if user_d:
            kwargs["user"] = EventRequestUser(**user_d)
        return cls(**kwargs)

    def serialize(self):
        d = {k: v for k, v in (("user_agent", self.user_agent),
                               ("ip", self.ip),
                               ("method", self.method),
                               ("path", self.path)) if v}
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
    def __init__(self, **kwargs):
        self._deserialized = kwargs.pop("_deserialized", False)
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
        self.probes = kwargs.pop('probes', [])
        self.incident_updates = kwargs.pop('incident_updates', [])
        self.tags = kwargs.pop('tags', [])
        self.routing_key = kwargs.pop('routing_key', None)
        self.objects = kwargs.pop('objects', {})

    def set_event(self, event):
        self.event = weakref.proxy(event)
        if not self._deserialized:
            self.add_objects(event.get_linked_objects_keys())

    @property
    def event_type(self):
        return self.event.event_type

    @property
    def namespace(self):
        return self.event.namespace or self.event_type

    @cached_property
    def all_tags(self):
        return set(self.tags + self.event.tags)

    @classmethod
    def deserialize(cls, event_d_metadata):
        kwargs = event_d_metadata.copy()
        kwargs["_deserialized"] = True
        kwargs['uuid'] = kwargs.pop('id')
        observer_d = kwargs.pop('observer', None)
        if observer_d:
            kwargs['observer'] = EventObserver.deserialize(observer_d)
        request_d = kwargs.pop('request', None)
        if request_d:
            kwargs['request'] = EventRequest.deserialize(request_d)
        kwargs['incident_updates'] = [IncidentUpdate.deserialize(u) for u in kwargs.pop('incident_updates', [])]
        kwargs['objects'] = {k: [decode_args(args) for args in v] for k, v in kwargs.pop('objects', {}).items()}
        return cls(**kwargs)

    def serialize(self, machine_metadata=True):
        d = {'created_at': self.created_at.isoformat(),
             'id': str(self.uuid),
             'index': self.index,
             'type': self.event_type,
             'namespace': self.namespace,
             }
        if self.all_tags:
            d['tags'] = list(self.all_tags)
        if self.routing_key:
            d['routing_key'] = self.routing_key
        if self.observer:
            d['observer'] = self.observer.serialize()
        if self.request:
            d['request'] = self.request.serialize()
        if self.probes:
            d['probes'] = self.probes
        if self.incident_updates:
            d['incident_updates'] = [u.serialize() for u in self.incident_updates]
        if self.machine_serial_number:
            d['machine_serial_number'] = self.machine_serial_number
        if self.objects:
            d['objects'] = {k: [encode_args(args) for args in v] for k, v in self.objects.items()}
        if not machine_metadata or not self.machine:
            return d
        elif self.machine:
            machine_d = self.machine.cached_serialized_info_for_event
            if machine_d:
                d['machine'] = machine_d
        return d

    def add_probe(self, probe, with_incident_updates=True):
        self.probes.append(probe.serialize_for_event_metadata())
        if not with_incident_updates:
            return
        try:
            incident_update = probe.get_matching_event_incident_update(self.event)
        except ReferenceError:
            # should not happen
            logger.error("Cannot compute probe event incident update")
        else:
            if incident_update is not None:
                self.incident_updates.append(incident_update)

    def add_objects(self, extra_objects):
        for extra_obj_key, extra_obj_args_list in extra_objects.items():
            if not extra_obj_args_list:
                # should never happen
                continue
            obj_args_list = self.objects.setdefault(extra_obj_key, [])
            for extra_obj_args in extra_obj_args_list:
                if extra_obj_args not in obj_args_list:
                    obj_args_list.append(extra_obj_args)

    def iter_loaded_probes(self):
        for serialized_probe in self.probes:
            probe_pk = serialized_probe["pk"]
            try:
                yield all_probes_dict[probe_pk]
            except KeyError:
                logger.error("Event %s/%s: unknown probe %s", self.uuid, self.index, probe_pk)


class BaseEvent(object):
    event_type = "base"
    namespace = None
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
        event_uuid = uuid.uuid4()
        for index, payload in enumerate(payloads):
            created_at = None
            if get_created_at:
                try:
                    created_at = get_created_at(payload)
                except Exception:
                    logger.exception("Could not extract created_at from payload")
                else:
                    if created_at is None:
                        logger.warning("Extracted created_at from %s payload is None", cls.event_type)
            metadata = EventMetadata(uuid=event_uuid, index=index,
                                     machine_serial_number=msn,
                                     observer=observer,
                                     request=request,
                                     created_at=created_at)
            yield cls(metadata, payload)

    @classmethod
    def post_machine_request_payloads(cls, msn, user_agent, ip, payloads, get_created_at=None, observer=None):
        for event in cls.build_from_machine_request_payloads(msn, user_agent, ip, payloads, get_created_at, observer):
            event.post()

    def __init__(self, metadata, payload):
        self.metadata = metadata
        self.payload = payload
        self.metadata.set_event(self)

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

    # linked objects

    def get_linked_objects_keys(self):
        return {}

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

    # heartbeats

    @classmethod
    def get_machine_heartbeat_timeout(cls, serial_number):
        return cls.heartbeat_timeout


register_event_type(BaseEvent)


# Zentral audit event


class AuditEvent(BaseEvent):

    class Action(Enum):
        CREATED = "created"
        UPDATED = "updated"
        DELETED = "deleted"

    event_type = "zentral_audit"
    tags = ["zentral"]

    @classmethod
    def build(
        cls,
        instance, action, prev_value=None,
        event_uuid=None, event_index=None,
        event_request=None
    ):
        em_kwargs = {"tags": [instance._meta.app_label]}
        if event_uuid is not None:
            em_kwargs["uuid"] = event_uuid
        if event_index is not None:
            em_kwargs["index"] = event_index
        if event_request:
            em_kwargs["request"] = event_request
        metadata = EventMetadata(**em_kwargs)
        try:
            metadata.add_objects(instance.linked_objects_keys_for_event())
        except AttributeError:
            key = instance._meta.verbose_name.replace(" ", "_")
            if instance._meta.app_label != "inventory":  # shorter names for the inventory objects
                key = f"{instance._meta.app_label}_{key}"
            metadata.add_objects({key: ((instance.pk,),)})
        # payload
        payload = {
            "action": action.value,
            "object": {
                "model": instance._meta.label_lower,
                "pk": str(instance.pk),
            }
        }
        if prev_value:
            payload["object"]["prev_value"] = prev_value
        if action in (cls.Action.CREATED, cls.Action.UPDATED):
            payload["object"]["new_value"] = instance.serialize_for_event()
        return cls(metadata, payload)

    @classmethod
    def build_from_request_and_instance(cls, request, instance, action, prev_value=None):
        event_request = EventRequest.build_from_request(request)
        return cls.build(
            instance, action, prev_value, event_request=event_request
        )


register_event_type(AuditEvent)


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
                    metadata = EventMetadata(machine_serial_number=serial_number,
                                             tags=tags)
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
    metadata = EventMetadata(machine_serial_number=reported_serial_number,
                             request=EventRequest.build_from_request(request))
    payload = {"module": module,
               "reported_machine_info": machine_info,
               "enrollment_serial_number": enrollment_serial_number}
    event = MachineConflictEvent(metadata, payload)
    event.post()
