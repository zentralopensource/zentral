import logging
from django.contrib.postgres.fields import ArrayField, JSONField
from django.urls import reverse
from django.db import models, transaction
from django.db.models import F, Func
from django.utils.text import slugify
from zentral.core.events import event_types
from zentral.core.probes.sync import signal_probe_change
from zentral.utils.dict import dict_diff
from . import probe_classes

logger = logging.getLogger('zentral.core.probes.models')


class Feed(models.Model):
    url = models.URLField(unique=True)
    name = models.TextField()
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)
    last_synced_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ('name',)

    def __str__(self):
        return self.name

    def get_absolute_url(self, anchor=None):
        return reverse("probes:feed", args=(self.pk,))


class FeedProbe(models.Model):
    feed = models.ForeignKey(Feed, on_delete=models.CASCADE)
    model = models.CharField(max_length=255)
    name = models.TextField()
    description = models.TextField(blank=True)
    key = models.CharField(max_length=255)
    body = JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    archived_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        unique_together = (('feed', 'key'),)
        ordering = ('model', 'name')

    def __str__(self):
        return self.name

    def get_probe_class(self):
        return probe_classes.get(self.model, None)

    def get_model_display(self):
        probe_class = self.get_probe_class()
        if probe_class:
            return probe_class.model_display
        else:
            return "Unknown probe class"


class ProbeSourceManager(models.Manager):
    def active(self):
        return self.filter(status=ProbeSource.ACTIVE)

    def current_models(self):
        qs = ProbeSource.objects.values("model").distinct().order_by()
        return sorted(((rd["model"], probe_classes[rd["model"]].model_display)
                       for rd in qs),
                      key=lambda t: t[1])

    def current_event_types(self):
        qs = (ProbeSource.objects.annotate(event_type=Func(F("event_types"), function="unnest"))
                                 .values("event_type").distinct().order_by())
        return sorted(((rd["event_type"], event_types[rd["event_type"]].get_event_type_display())
                       for rd in qs),
                      key=lambda t: t[1])

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
    model = models.CharField(max_length=255, blank=True, null=True, editable=False)
    name = models.CharField(max_length=255, unique=True)
    slug = models.SlugField(max_length=255, unique=True, editable=False)
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default=INACTIVE)
    description = models.TextField(blank=True)
    # auto fields for search / filtering
    event_types = ArrayField(models.CharField(max_length=255), blank=True, editable=False)

    feed_probe = models.ForeignKey(FeedProbe, blank=True, null=True, editable=False, on_delete=models.SET_NULL)
    feed_probe_last_synced_at = models.DateTimeField(blank=True, null=True)
    feed_probe_update_available = models.BooleanField(default=False)

    body = JSONField(editable=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = ProbeSourceManager()

    class Meta:
        ordering = ('name', 'id')

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        self.slug = slugify(self.name)
        probe = self.load()
        self.model = probe.get_model()
        if not probe.loaded:
            logger.warning("Probe %s not loaded => probe source INACTIVE", self.pk)
            self.status = ProbeSource.INACTIVE
        # denormalize event_types for UI filtering
        # TODO: Json filtering in the query ?
        self.event_types = [etc.event_type for etc in probe.get_event_type_classes()]
        super(ProbeSource, self).save(*args, **kwargs)
        transaction.on_commit(signal_probe_change)

    def get_probe_class(self):
        return probe_classes.get(self.model, None)

    def get_model_display(self):
        probe_class = self.get_probe_class()
        if probe_class:
            return probe_class.model_display
        else:
            return "Unknown probe class"

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

    def get_actions_absolute_url(self):
        return self.get_absolute_url("actions")

    def get_filters_absolute_url(self):
        return self.get_absolute_url("filters")

    def load(self):
        probe_cls = probe_classes.get(self.model)
        if not probe_cls:
            probe_cls = probe_classes.get("BaseProbe")  # always present
        return probe_cls(self)

    def update_body(self, func):
        func(self.body)
        self.save()

    def update_action(self, action_name, action_config_d):
        def func(probe_d):
            actions = probe_d.setdefault("actions", {})
            actions[action_name] = action_config_d
        self.update_body(func)

    def delete_action(self, action_name):
        def func(probe_d):
            if "actions" in probe_d:
                probe_d["actions"].pop(action_name, None)
        self.update_body(func)

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

    # update

    def update_diff(self):
        if not self.feed_probe:
            return {}
        probe = self.load()
        current_body = probe.export()["body"]
        return dict_diff(current_body, self.feed_probe.body)

    def skip_update(self):
        if self.feed_probe_update_available:
            self.feed_probe_update_available = False
            self.save()

    def apply_update(self):
        update_diff = self.update_diff()
        if not update_diff:
            if self.feed_probe_update_available:
                self.feed_probe_update_available = False
                self.save()
            return
        body = self.body
        for key, kdiff in update_diff.items():
            removed = kdiff.get("removed")
            added = kdiff.get("added")
            if isinstance(added, list) or isinstance(removed, list):
                val = body.get(key, [])
                for removed_item in (removed or []):
                    val.remove(removed_item)
                for added_item in (added or []):
                    val.append(added_item)
                if val:
                    body[key] = val
                elif key in body:
                    del body[key]
            else:
                if added:
                    body[key] = added
                elif key in body:
                    del body[key]
        self.feed_probe_update_available = False
        self.save()
