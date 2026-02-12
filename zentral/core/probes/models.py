import logging
import uuid

from django.contrib.postgres.fields import ArrayField
from django.db import models, transaction
from django.db.models import Count, F, Func
from django.urls import reverse
from django.utils.text import slugify

from zentral.core.events import event_types
from zentral.core.incidents.models import Severity
from zentral.core.probes.sync import signal_probe_change
from zentral.utils.backend_model import BackendInstance

from .action_backends import ActionBackend, get_action_backend

logger = logging.getLogger('zentral.core.probes.models')


class ActionManager(models.Manager):
    def for_deletion(self):
        return self.annotate(
            # no probes
            probe_count=Count("probesource")
        ).filter(
            probe_count=0
        )


class Action(BackendInstance):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    backend = models.CharField(choices=ActionBackend.choices)
    backend_enum = ActionBackend

    objects = ActionManager()

    def get_backend(self, load=False):
        return get_action_backend(self, load)

    def can_be_deleted(self):
        return Action.objects.for_deletion().filter(pk=self.pk).exists()


class ProbeSourceManager(models.Manager):
    def active(self):
        return self.filter(status=ProbeSource.ACTIVE)

    def current_event_types(self):
        qs = (ProbeSource.objects.annotate(event_type=Func(F("event_types"), function="unnest"))
                                 .values("event_type").distinct().order_by())
        cet = []
        for rd in qs:
            event_type = rd["event_type"]
            if event_type in event_types:
                event_type_display = event_types[rd["event_type"]].get_event_type_display()
            else:
                event_type_display = event_type.replace("_", " ")
            cet.append((event_type, event_type_display))
        cet.sort(key=lambda t: t[1])
        return cet

    def clone(self, probe_source, name):
        probe_source.id = None
        probe_source.name = name
        probe_source.status = ProbeSource.INACTIVE
        probe_source.save()
        return probe_source


class ProbeSource(models.Model):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    STATUS_CHOICES = (
        (ACTIVE, "Active"),
        (INACTIVE, "Inactive"),
    )
    name = models.CharField(max_length=255, unique=True)
    slug = models.SlugField(max_length=255, unique=True, editable=False)
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default=INACTIVE)
    description = models.TextField(blank=True)
    # auto fields for search / filtering
    event_types = ArrayField(models.CharField(max_length=255), blank=True, editable=False)

    actions = models.ManyToManyField(Action, blank=True)

    body = models.JSONField(editable=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = ProbeSourceManager()

    class Meta:
        ordering = ('name', 'id')

    def __str__(self):
        return self.name

    @property
    def active(self):
        return self.status == self.ACTIVE

    @property
    def inventory_filters(self):
        return self.body.get("filters", {}).get("inventory", [])

    @property
    def metadata_filters(self):
        return self.body.get("filters", {}).get("metadata", [])

    @property
    def payload_filters(self):
        return self.body.get("filters", {}).get("payload", [])

    @property
    def incident_severity(self):
        try:
            return Severity(self.body.get("incident_severity"))
        except ValueError:
            pass

    def save(self, *args, **kwargs):
        self.slug = slugify(self.name)
        from .probe import Probe
        probe = Probe(self)
        if not probe.loaded:
            logger.warning("Probe %s not loaded → probe source INACTIVE", self.pk)
            self.status = ProbeSource.INACTIVE
        # denormalize event_types for UI filtering
        # TODO: Json filtering in the query ?
        self.event_types = [etc.event_type for etc in probe.get_event_type_classes()]
        super(ProbeSource, self).save(*args, **kwargs)
        transaction.on_commit(signal_probe_change)

    def get_event_type_classes(self):
        return [etc for etc in (event_types.get(et, None) for et in self.event_types) if etc]

    def get_event_type_class_names(self):
        return [etc.get_event_type_display() for etc in self.get_event_type_classes()]

    def delete(self, *args, **kwargs):
        super(ProbeSource, self).delete(*args, **kwargs)
        transaction.on_commit(signal_probe_change)

    def get_absolute_url(self, anchor=None):
        url = reverse("probes:probe", args=(self.pk,))
        if anchor:
            url = "{}#{}".format(url, anchor)
        return url

    def get_filters_absolute_url(self):
        return self.get_absolute_url("filters")

    def update_body(self, func):
        func(self.body)
        self.save()

    def append_filter(self, filter_section, filter_d):
        def func(probe_d):
            filters = probe_d.setdefault("filters", {})
            filter_section_l = filters.setdefault(filter_section, [])
            filter_section_l.append(filter_d)
        self.update_body(func)

    def update_filter(self, filter_section, filter_id, filter_d):
        def func(probe_d):
            filter_section_l = probe_d["filters"][filter_section]
            filter_section_l[filter_id] = filter_d
        self.update_body(func)

    def delete_filter(self, filter_section, filter_id):
        def func(probe_d):
            filter_section_l = probe_d["filters"][filter_section]
            filter_section_l.pop(filter_id)
        self.update_body(func)

    def serialize_for_event(self):
        d = {
            "pk": self.pk,
            "name": self.name,
            "slug": self.slug,
            "description": self.description,
            "active": self.active,
            "actions": [a.serialize_for_event(keys_only=True) for a in self.actions.all().order_by("pk")],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
        if self.description:
            d["description"] = self.description
        if self.incident_severity:
            d["incident_severity"] = self.incident_severity.value
        for filter_type in ("inventory", "metadata", "payload"):
            filter_attr = f"{filter_type}_filters"
            filters = getattr(self, filter_attr)
            if filters:
                d[filter_attr] = filters
        return d
