from django.db import models


class LastReport(models.Model):
    machine_serial_number = models.CharField(max_length=64, unique=True)
    munki_version = models.CharField(max_length=32, blank=True, null=True)
    user_agent = models.CharField(max_length=64)
    ip = models.GenericIPAddressField(blank=True, null=True)
    sha1sum = models.CharField(max_length=40)
    run_type = models.CharField(max_length=64)
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    last_seen = models.DateTimeField(auto_now=True)
