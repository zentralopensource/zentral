from enum import Enum
import logging
from django.db import models
from django.utils.functional import cached_property
from . import compliance_check_class_from_model


logger = logging.getLogger('zentral.core.compliance_checks.models')


class ComplianceCheck(models.Model):
    model = models.CharField(max_length=256, editable=False)
    name = models.TextField()
    description = models.TextField(blank=True)
    version = models.PositiveIntegerField(default=1, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("model", "name"),)

    def __str__(self):
        return self.name

    def serialize_for_event(self):
        return {
            "pk": self.pk,
            "model": self.model,
            "name": self.name,
            "description": self.description,
            "version": self.version
        }

    @cached_property
    def loaded_compliance_check(self):
        cls = compliance_check_class_from_model(self.model)
        return cls(self)


class Status(Enum):
    OK = 0
    PENDING = 100
    UNKNOWN = 200
    FAILED = 300

    def __str__(self):
        if self.name == "OK":
            return self.name
        else:
            return self.name.title()

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented

    def display_class(self):
        if self == self.OK:
            return "success"
        elif self == self.FAILED:
            return "danger"
        elif self == self.UNKNOWN:
            return "warning"
        else:
            return ""

    @classmethod
    def choices(cls):
        return tuple((i.value, str(i)) for i in cls if i != cls.PENDING)


class MachineStatus(models.Model):
    compliance_check = models.ForeignKey(ComplianceCheck, on_delete=models.CASCADE)
    compliance_check_version = models.PositiveIntegerField()
    serial_number = models.TextField()
    status = models.PositiveSmallIntegerField(choices=Status.choices())
    status_time = models.DateTimeField()
    previous_status = models.PositiveSmallIntegerField(choices=Status.choices(), null=True)

    class Meta:
        unique_together = (("compliance_check", "serial_number",))
