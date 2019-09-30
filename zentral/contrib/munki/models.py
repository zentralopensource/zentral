from django.db import models
from django.urls import reverse
from zentral.contrib.inventory.models import BaseEnrollment


# enrollment


class Enrollment(BaseEnrollment):
    def get_absolute_url(self):
        return "{}#enrollment_{}".format(reverse("munki:enrollment_list"), self.pk)

    def get_description_for_distributor(self):
        return "Munki enrollment"


class EnrolledMachine(models.Model):
    enrollment = models.ForeignKey(Enrollment, on_delete=models.CASCADE)
    serial_number = models.TextField(db_index=True)
    token = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)


# munki state


class MunkiState(models.Model):
    machine_serial_number = models.CharField(max_length=64, unique=True)
    munki_version = models.CharField(max_length=32, blank=True, null=True)
    user_agent = models.CharField(max_length=64)
    ip = models.GenericIPAddressField(blank=True, null=True)
    sha1sum = models.CharField(max_length=40, blank=True, null=True)
    run_type = models.CharField(max_length=64, blank=True, null=True)
    start_time = models.DateTimeField(blank=True, null=True)
    end_time = models.DateTimeField(blank=True, null=True)
    last_seen = models.DateTimeField(auto_now=True)
