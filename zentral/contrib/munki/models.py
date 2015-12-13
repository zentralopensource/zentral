from django.db import models


class MunkiState(models.Model):
    machine_serial_number = models.CharField(max_length=64, unique=True)
    munki_version = models.CharField(max_length=32, blank=True, null=True)
    user_agent = models.CharField(max_length=64)
    ip = models.GenericIPAddressField(blank=True, null=True)
    sha1sum = models.CharField(max_length=40, blank=True, null=True)
    run_type = models.CharField(max_length=64, blank=True, null=True)
    start_time = models.DateTimeField(blank=True, null=True)
    end_time = models.DateTimeField(blank=True, null=True)
    binaryinfo_last_seen = models.DateTimeField(blank=True, null=True)
    last_seen = models.DateTimeField(auto_now=True)
