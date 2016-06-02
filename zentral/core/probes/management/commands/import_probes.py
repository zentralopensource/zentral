import logging
import os.path
from django.core.management.base import BaseCommand
import yaml
from zentral.conf.utils import load_config_file
from zentral.core.exceptions import ImproperlyConfigured
from zentral.core.probes.models import ProbeSource

logger = logging.getLogger("zentral.core.probes.management."
                           "commands.import_probes")


class Command(BaseCommand):
    help = 'Import JSON or YAML probes'

    def add_arguments(self, parser):
        parser.add_argument('probe_file', nargs='+', type=str)

    def handle(self, **options):
        for probe_file in options['probe_file']:
            probe_basename = os.path.basename(probe_file)
            try:
                loaded_probe = load_config_file(probe_file)
            except ImproperlyConfigured:
                logger.error("Probe %s not imported. Syntax Error ?",
                             probe_basename)
                continue
            name = loaded_probe.pop('name', probe_basename)
            description = loaded_probe.pop('description', None)
            defaults = {"body": yaml.safe_dump(loaded_probe,
                                               default_flow_style=False,
                                               default_style='')}
            if description:
                defaults['description'] = description
            _, created = ProbeSource.objects.get_or_create(name=name,
                                                           defaults=defaults)
            if not created:
                logger.warning("Probe %s / %s not imported. Already in DB ?",
                               name, probe_basename)
            else:
                logger.debug("Probe %s / %s imported.",
                             name, probe_basename)
