import logging
from django.db import models
from django.utils.text import slugify
import yaml

logger = logging.getLogger('zentral.core.probes.models')


class ProbeManager(models.Manager):
    def active(self):
        return self.filter(status="ACTIVE")


class Probe(models.Model):
    STATUS_CHOICES = (
      ("ACTIVE", "Active"),
      ("INACTIVE", "Inactive"),
    )
    name = models.CharField(max_length=255, unique=True)
    slug = models.SlugField(max_length=255, unique=True)
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default="ACTIVE")
    description = models.TextField(blank=True)

    body = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = ProbeManager()

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        self.slug = slugify(self.name)
        super(Probe, self).save(*args, **kwargs)

    def load(self):
        err_list = []
        try:
            probe_d = yaml.load(self.body)
        except yaml.parser.ParserError:
            err_list.append("Could not parse probe body")
        if not isinstance(probe_d, dict):
            err_list.append("Probe body should be a hash/dict")
        else:
            if "name" in probe_d:
                err_list.append("name key in probe body")
            else:
                probe_d['name'] = self.name
            if "description" in probe_d:
                err_list.append("description key in probe body")
            elif self.description:
                probe_d['description'] = self.description
            # TODO import loop !!!
            from zentral.core.actions import actions
            # TODO import loop !!!
            for action_name, action_config_d in probe_d.pop("actions", {}).items():
                try:
                    action = actions[action_name]
                except KeyError:
                    err_list.append("unknown action %s" % action_name)
                else:
                    probe_d.set_default("actions", []).append((action, action_config_d))
        return probe_d
