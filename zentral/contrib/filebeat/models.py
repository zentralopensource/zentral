import logging
from django.db import models
from django.urls import reverse
from zentral.contrib.inventory.models import BaseEnrollment

logger = logging.getLogger("zentral.contrib.filebeat.models")


# Configuration / Enrollment


class Configuration(models.Model):
    name = models.CharField(max_length=256, unique=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("filebeat:configuration", args=(self.pk,))

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        for enrollment in self.enrollment_set.all():
            # per default, will bump the enrollment version
            # and notify their distributors
            enrollment.save()


class Enrollment(BaseEnrollment):
    configuration = models.ForeignKey(Configuration, on_delete=models.CASCADE)
    filebeat_release = models.CharField(max_length=64, blank=True, null=True)

    def get_description_for_distributor(self):
        return "Filebeat configuration: {}".format(self.configuration)

    def serialize_for_event(self):
        enrollment_dict = super().serialize_for_event()
        enrollment_dict["configuration"] = {"pk": self.configuration.pk,
                                            "name": self.configuration.name}
        return enrollment_dict

    def get_absolute_url(self):
        return "{}#enrollment_{}".format(reverse("filebeat:configuration", args=(self.configuration.pk,)), self.pk)


class EnrolledMachine(models.Model):
    enrollment = models.ForeignKey(Enrollment, on_delete=models.CASCADE)
    serial_number = models.TextField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
