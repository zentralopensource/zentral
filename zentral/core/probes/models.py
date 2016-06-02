import logging
from django.core.exceptions import ValidationError
from django.core.urlresolvers import reverse
from django.db import models, transaction
from django.utils.text import slugify
from zentral.core.exceptions import ImproperlyConfigured
from . import load_probe

logger = logging.getLogger('zentral.core.probes.models')


class ProbeSourceManager(models.Manager):
    def active(self):
        return self.filter(status="ACTIVE")


def validate_body(value):
    try:
        load_probe(ProbeSource(name="validation", body=value))
    except ImproperlyConfigured as e:
        message = ", ".join(e.err_list)
        raise ValidationError(
            message,
            params={'err_list': e.err_list},
        )


class ProbeSource(models.Model):
    STATUS_CHOICES = (
        ("ACTIVE", "Active"),
        ("INACTIVE", "Inactive"),
    )
    name = models.CharField(max_length=255, unique=True)
    slug = models.SlugField(max_length=255, unique=True)
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default="ACTIVE")
    description = models.TextField(blank=True)

    body = models.TextField(validators=[validate_body])

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = ProbeSourceManager()

    class Meta:
        ordering = ('name', 'id')

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        self.slug = slugify(self.name)
        super(ProbeSource, self).save(*args, **kwargs)
        from zentral.core.queues import queues
        transaction.on_commit(queues.signal_probe_change)

    def delete(self, *args, **kwargs):
        super(ProbeSource, self).delete(*args, **kwargs)
        from zentral.core.queues import queues
        transaction.on_commit(queues.signal_probe_change)

    def get_absolute_url(self):
        return reverse("probes:probe", args=(self.pk,))

    def load(self):
        return load_probe(self)
