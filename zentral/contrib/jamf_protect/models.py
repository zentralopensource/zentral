import logging
from django.db import models
from django.urls import reverse
from zentral.contrib.inventory.models import BaseEnrollment


logger = logging.getLogger("zentral.contrib.jamf_protect.models")


class Enrollment(BaseEnrollment):
    def get_absolute_url(self):
        return "{}#enrollment_{}".format(reverse("jamf_protect:enrollments"), self.pk)


class EnrolledMachine(models.Model):
    enrollment = models.ForeignKey(Enrollment, on_delete=models.CASCADE)
    serial_number = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("enrollment", "serial_number")
