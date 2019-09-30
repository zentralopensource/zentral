import logging
from django.db import models
from django.db.models import Q
from django.urls import reverse
from django.utils.translation import ugettext_lazy as _


logger = logging.getLogger('zentral.core.incidents.models')

# severity
SEVERITY_CRITICAL = 300
SEVERITY_MAJOR = 200
SEVERITY_MINOR = 100
SEVERITY_CHOICES = (
    (SEVERITY_CRITICAL, _("Critical")),
    (SEVERITY_MAJOR, _("Major")),
    (SEVERITY_MINOR, _("Minor"))
)
SEVERITY_CHOICES_DICT = dict(SEVERITY_CHOICES)

# status
STATUS_OPEN = "OPEN"
STATUS_IN_PROGRESS = "IN_PROGRESS"
STATUS_RESOLVED = "RESOLVED"
STATUS_CLOSED = "CLOSED"
STATUS_REOPENED = "REOPENED"
STATUS_CHOICES = (
    (STATUS_OPEN, _("Open")),
    (STATUS_IN_PROGRESS, _("In Progress")),
    (STATUS_RESOLVED, _("Resolved")),
    (STATUS_CLOSED, _("Closed")),
    (STATUS_REOPENED, _("Reopened")),
)
STATUS_CHOICES_DICT = dict(STATUS_CHOICES)
OPEN_STATUSES = {STATUS_OPEN, STATUS_IN_PROGRESS, STATUS_REOPENED}
CLOSED_STATUSES = {STATUS_CLOSED, STATUS_RESOLVED}


def get_next_statuses(current_status):
    if current_status in [STATUS_OPEN, STATUS_REOPENED]:
        return [STATUS_IN_PROGRESS, STATUS_CLOSED, STATUS_RESOLVED]
    elif current_status == STATUS_IN_PROGRESS:
        return [STATUS_CLOSED, STATUS_RESOLVED]
    elif current_status in [STATUS_CLOSED, STATUS_RESOLVED]:
        return [STATUS_REOPENED]


class Incident(models.Model):
    probe_source = models.ForeignKey("probes.ProbeSource", on_delete=models.SET_NULL, blank=True, null=True)
    name = models.TextField()
    description = models.TextField(blank=True)
    severity = models.PositiveIntegerField(choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=64, choices=STATUS_CHOICES)
    event_id = models.UUIDField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)
        constraints = [
            models.UniqueConstraint(
                name="one_open_incident_per_probe",
                fields=["probe_source"],
                condition=Q(status__in=OPEN_STATUSES)
            )
        ]

    def get_absolute_url(self):
        return reverse("incidents:incident", args=(self.pk,))

    def serialize_for_event_metadata(self):
        # to be included in the triggering events metadata
        # do not include the original event_id
        return {
            "pk": self.pk,
            "probe_pk": self.probe_source.pk,
            "name": self.name,
            "severity": self.severity,
            "status": self.status,
        }

    def serialize_for_event(self):
        # payload of the incident events
        d = self.serialize_for_event_metadata()
        d["event_id"] = str(self.event_id)
        return d

    def get_next_statuses(self):
        next_statuses = get_next_statuses(self.status)
        if self.machineincident_set.filter(status__in=OPEN_STATUSES).count():
            for status in (STATUS_CLOSED, STATUS_RESOLVED):
                try:
                    next_statuses.remove(status)
                except ValueError:
                    pass
        return next_statuses

    def get_next_status_choices(self):
        return [(s, l) for s, l in STATUS_CHOICES if s in self.get_next_statuses()]


class MachineIncident(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE)
    serial_number = models.TextField(db_index=True)
    status = models.CharField(max_length=64, choices=STATUS_CHOICES)
    event_id = models.UUIDField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)
        constraints = [
            models.UniqueConstraint(
                name="one_open_machine_incident_per_incident",
                fields=["incident", "serial_number"],
                condition=Q(status__in=OPEN_STATUSES)
            )
        ]

    def get_absolute_url(self):
        return "{}#{}".format(reverse("incidents:incident", args=(self.incident.pk,)), self.pk)

    def _serialize(self, include_event_id=True):
        d = {
            "pk": self.pk,
            "status": self.status,
        }
        if include_event_id:
            d["event_id"] = str(self.event_id)
        return d

    def serialize_for_event_metadata(self):
        # to be included in the triggering events metadata
        # serialize as an incident with an embedded machine event
        # this way we always have an incident as the outermost object in the event metadata
        # do not include the original event_id
        d = self.incident.serialize_for_event_metadata()
        d["machine_incident"] = self._serialize(include_event_id=False)
        return d

    def serialize_for_event(self):
        # serialize as a machine incident with an embedded incident
        d = self._serialize()
        d["incident"] = self.incident.serialize_for_event()
        return d

    def get_next_statuses(self):
        return get_next_statuses(self.status)

    def get_next_status_choices(self):
        return [(s, l) for s, l in STATUS_CHOICES if s in self.get_next_statuses()]
