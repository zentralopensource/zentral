import logging
from django.db import models
from django.db.models import Q
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
OPEN_STATUSES = {STATUS_OPEN, STATUS_IN_PROGRESS, STATUS_REOPENED}
CLOSED_STATUSES = {STATUS_CLOSED, STATUS_RESOLVED}


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

    def serialize_for_event(self):
        return {
            "pk": self.pk,
            "name": self.name,
            "severity": self.severity,
            "status": self.status,
            "event_id": str(self.event_id),
        }


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

    def serialize_for_event(self):
        d = self.incident.serialize_for_event()
        d["machine_incident"] = {
            "pk": self.pk,
            "status": self.status,
            "event_id": str(self.event_id),
        }
        return d
