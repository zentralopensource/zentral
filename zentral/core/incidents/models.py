from enum import Enum
import logging
from typing import NamedTuple
from django.contrib.postgres.fields import JSONField
from django.db import models
from django.db.models import Q
from django.urls import reverse
from django.utils.functional import cached_property
from . import incident_class_from_type


logger = logging.getLogger('zentral.core.incidents.models')


class Severity(Enum):
    CRITICAL = 300
    MAJOR = 200
    MINOR = 100
    NONE = 0

    def __str__(self):
        return self.name.title()

    @classmethod
    def choices(cls):
        return tuple((i.value, str(i)) for i in cls if i != cls.NONE)


class Status(Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    REOPENED = "REOPENED"

    def __str__(self):
        return self.name.replace("_", " ").title()

    @classmethod
    def choices(cls):
        return tuple((i.value, str(i)) for i in cls)

    @classmethod
    def open_values(cls):
        return {cls.OPEN.value, cls.IN_PROGRESS.value, cls.REOPENED.value}

    @classmethod
    def closed_values(cls):
        return {cls.CLOSED.value, cls.RESOLVED.value}

    def next_statuses(self):
        if self == Status.OPEN or self == Status.REOPENED:
            return [Status.IN_PROGRESS, Status.CLOSED, Status.RESOLVED]
        elif self == Status.IN_PROGRESS:
            return [Status.CLOSED, Status.RESOLVED]
        elif self == Status.CLOSED or self == Status.RESOLVED:
            return [Status.REOPENED]


class IncidentUpdate(NamedTuple):
    incident_type: str
    key: dict
    severity: Severity

    @classmethod
    def deserialize(cls, incident_update_d):
        return cls(
            incident_type=incident_update_d["incident_type"],
            key=incident_update_d["key"],
            severity=Severity(incident_update_d["severity"])
        )

    def serialize(self):
        d = self._asdict()
        d["severity"] = d["severity"].value
        return d


class Incident(models.Model):
    incident_type = models.CharField(max_length=256)
    key = JSONField()
    severity = models.PositiveIntegerField(choices=Severity.choices())
    name = models.TextField()
    status = models.CharField(max_length=64, choices=Status.choices())
    status_time = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                name="one_open_incident_per_incident_type_and_key",
                fields=["incident_type", "key"],
                condition=Q(status__in=Status.open_values())
            ),
        ]
        indexes = [
            models.Index(fields=["incident_type", "key"]),
        ]
        ordering = ("-created_at",)

    def get_absolute_url(self):
        return reverse("incidents:incident", args=(self.pk,))

    def serialize_for_event(self):
        return {
            "pk": self.pk,
            "type": self.incident_type,
            "key": self.key,
            "severity": self.severity,
            "status": self.status,
            "status_time": self.status_time
        }

    def get_next_statuses(self):
        next_statuses = Status(self.status).next_statuses()
        if self.machineincident_set.filter(status__in=Status.open_values()).count():
            for status in (Status.CLOSED, Status.RESOLVED):
                try:
                    next_statuses.remove(status)
                except ValueError:
                    pass
        return next_statuses

    def get_next_status_choices(self):
        return [(s.value, str(s)) for s in self.get_next_statuses()]

    @cached_property
    def loaded_incident(self):
        cls = incident_class_from_type(self.incident_type)
        return cls(self)

    def save(self, *args, **kwargs):
        if not self.pk:
            self.name = self.loaded_incident.get_name()
        return super().save(*args, **kwargs)


class MachineIncident(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE)
    serial_number = models.TextField(db_index=True)
    status = models.CharField(max_length=64, choices=Status.choices())
    status_time = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)
        constraints = [
            models.UniqueConstraint(
                name="one_open_machine_incident_per_incident",
                fields=["incident", "serial_number"],
                condition=Q(status__in=Status.open_values())
            )
        ]

    def get_absolute_url(self):
        return "{}#{}".format(reverse("incidents:incident", args=(self.incident.pk,)), self.pk)

    def serialize_for_event(self):
        d = self.incident.serialize_for_event()
        d["machine_incident"] = {
            "pk": self.pk,
            "status": self.status,
            "status_time": self.status_time
        }
        return d

    def get_next_statuses(self):
        return Status(self.status).next_statuses()

    def get_next_status_choices(self):
        return [(s.value, str(s)) for s in self.get_next_statuses()]
